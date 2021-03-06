require 'devise_pam_authenticatable/strategy'

module Devise
  module Models
    module PamAuthenticatable

      def find_pam_service
        return self.class.pam_service if self.class.instance_variable_defined?('@pam_service')
        ::Devise.pam_default_service
      end

      def find_pam_suffix
        return self.class.pam_suffix if self.class.instance_variable_defined?('@pam_suffix')
        ::Devise.pam_default_suffix
      end

      def pam_get_name
        return self[::Devise.usernamefield] if ::Devise.usernamefield && self[::Devise.usernamefield]
        return nil unless ::Devise.emailfield && (suffix = find_pam_suffix)
        # Regex is vulnerable to DOS attacks, use newline instead
        email = "#{self[::Devise.emailfield]}\n"
        pos = email.index("@#{suffix}\n")
        # deceptive emailaddresses use newlines, so check this here
        # and return nil in case another newline is found.
        # warning: don't try to optimize with '' \n. Escapes doesn't work in ''
        return nil if !pos || email.count("\n") > 1
        email.slice(0, pos)
      end

      def pam_managed_user?
        return false unless pam_get_name
        Rpam2.account(find_pam_service, pam_get_name)
      end

      def pam_conflict?
        # detect a conflict
        # use blank password as discriminator between traditional login and pam login
        respond_to?('encrypted_password') && encrypted_password.present? && pam_managed_user?
      end

      def pam_conflict(_attributes)
        # solve conflict between other and pam related user accounts
        # to disable login with pam return nil elsewise return a (different?) user object
        # as default assume the conflict ok and return user object unchanged
        self
      end

      def pam_setup(attributes)
        return unless ::Devise.emailfield && ::Devise.usernamefield
        self[::Devise.emailfield] = Rpam2.getenv(find_pam_service, pam_get_name, attributes[:password], 'email', false)
        self[::Devise.emailfield] = attributes[::Devise.emailfield] if self[::Devise.emailfield].nil?
        self[::Devise.emailfield] = "#{self[::Devise.usernamefield]}@#{find_pam_suffix}" if self[::Devise.emailfield].nil? && find_pam_suffix
      end

      # Checks if a resource is valid upon authentication.
      def pam_authentication(pw, request = nil)
        return nil unless pam_get_name
        rhost = request.remote_ip if request rescue nil
        Rpam2.auth(find_pam_service, pam_get_name, pw, nil, rhost)
      end

      module ClassMethods
        Devise::Models.config(self, :pam_service, :pam_suffix)

        def pam_get_user(attributes = {})
          if ::Devise.usernamefield && attributes[:username]
            resource = find_by(::Devise.usernamefield => attributes[:username])

            if resource.blank?
              resource = new(::Devise.usernamefield => attributes[:username])
            end
            resource
          elsif ::Devise.emailfield && attributes[:email]
            resource =
              if ::Devise.check_at_sign && ::Devise.usernamefield && !attributes[:email].index('@')
                find_by(::Devise.usernamefield => attributes[:email])
              else
                find_by(::Devise.emailfield => attributes[:email])
              end

            if resource.blank?
              resource = new
              if ::Devise.check_at_sign && !attributes[:email].index('@')
                if ::Devise.usernamefield
                  # use email as username
                  resource[::Devise.usernamefield] = attributes[:email]
                end
                if (email = Rpam2.getenv(resource.find_pam_service, attributes[:email], attributes[:password], 'email', false))
                  # set email if found in pam
                  resource[::Devise.emailfield] = email
                end
              else
                resource[::Devise.emailfield] = attributes[:email]
              end
            end
            resource
          end
        end

        def authenticate_with_pam(attributes = {})
          return nil unless attributes[:password]

          return nil unless (resource = pam_get_user(attributes))

          # potential conflict detected
          resource = resource.pam_conflict(attributes) if resource.pam_conflict?

          return nil unless resource && resource.try(:pam_authentication, attributes[:password], attributes[:request])
          if resource.new_record?
            resource.pam_setup(attributes)
            resource.save!
          end
          resource
        end
      end
    end
  end
end

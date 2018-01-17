require 'devise_pam_authenticatable/strategy'

module Devise
  module Models
    module PamAuthenticatable

      def get_service
        return self.class.pam_service if self.class.instance_variable_defined?('@pam_service')
        ::Devise.pam_default_service
      end

      def get_suffix
        return self.class.pam_suffix if self.class.instance_variable_defined?('@pam_suffix')
        ::Devise.pam_default_suffix
      end

      def on_pam_conflict(_attributes)
        # to disable login with pam return nil elsewise return a (different?) user object
        # as default assume there is never a conflict and return user object
        self
      end

      def is_pam_conflict
        # use blank password as discriminator between traditional login and pam login?
        is_pam_account && resource.respond_to?('password') && resource.password.present?
      end

      def is_pam_account
        return false unless get_pam_name
        Rpam2.account(get_service, get_pam_name)
      end

      def pam_setup(attributes)
        return unless ::Devise.emailfield && ::Devise.usernamefield
        self[::Devise.emailfield] = Rpam2.getenv(get_service, get_pam_name, attributes[:password], 'email', false)
        self[::Devise.emailfield] = attributes[::Devise.emailfield] if self[::Devise.emailfield].nil?
        self[::Devise.emailfield] = "#{self[::Devise.usernamefield]}@#{get_suffix}" if self[::Devise.emailfield].nil? && get_suffix
      end

      def password_required?
        false
      end

      def get_pam_name
        return self[::Devise.usernamefield] if ::Devise.usernamefield && self[::Devise.usernamefield]
        suffix = get_suffix
        return nil unless suffix && ::Devise.emailfield
        email = "#{self[::Devise.emailfield]}\n"
        pos = email.index("@#{suffix}\n")
        return nil unless pos
        email.slice(0, pos)
      end

      # Checks if a resource is valid upon authentication.
      def valid_pam_authentication?(pw)
        return nil unless get_pam_name
        Rpam2.auth(get_service, get_pam_name, pw)
      end

      module ClassMethods
        Devise::Models.config(self, :pam_service, :pam_suffix)

        def authenticate_with_pam(attributes = {})
          return nil unless attributes[:password]
          if ::Devise.usernamefield && attributes[:username]
            resource = find_by(::Devise.usernamefield => attributes[:username])

            if resource.blank?
              resource = new
              resource[::Devise.usernamefield] = attributes[:username]
            end
          elsif ::Devise.emailfield
            return nil unless attributes[:email]
            resource = find_by(::Devise.emailfield => attributes[:email])

            if resource.blank?
              resource = new
              if ::Devise.check_at_sign && ::Devise.usernamefield && attributes[:email].index('@').nil?
                # use email as username
                resource[::Devise.usernamefield] = attributes[:email]
              else
                resource[::Devise.emailfield] = attributes[:email]
              end
            end
          else
            return nil
          end

          # potential conflict detected
          resource = resource.on_pam_conflict(attributes) if resource.is_pam_conflict

          return nil unless resource && resource.try(:valid_pam_authentication?, attributes[:password])
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

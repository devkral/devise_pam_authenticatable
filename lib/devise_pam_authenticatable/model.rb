require 'devise_pam_authenticatable/strategy'

module Devise
  module Models
    module PamAuthenticatable
      def self.included(base)
        base.class_eval do
          extend ClassMethods
          attr_accessor :password
        end
      end

      def self.required_fields(_klass)
        []
      end

      def get_service
        return self.class.pam_service if self.class.instance_variable_defined?('@pam_service')
        ::Devise.pam_default_service
      end

      def get_suffix
        return self.class.pam_suffix if self.class.instance_variable_defined?('@pam_suffix')
        ::Devise.pam_default_suffix
      end

      def pam_on_filled_pw(_attributes)
        # use blank password as discriminator between traditional login and pam login?
        # to disable login with pam return nil elsewise return a (different?) user object
        # as default assume there is no conflict and return user object
        self
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
      def valid_pam_authentication?(password)
        Rpam2.auth(get_service, get_pam_name, password)
      end

      module ClassMethods
        Devise::Models.config(self, :pam_service, :pam_suffix)

        def authenticate_with_pam(attributes = {})
          if ::Devise.usernamefield && attributes[:username]
            resource = where(::Devise.usernamefield => attributes[:username]).first

            if resource.blank?
              resource = new
              resource[::Devise.usernamefield] = attributes[:username]
            end
          elsif ::Devise.emailfield
            return nil unless attributes[:email]
            resource = where(::Devise.emailfield => attributes[:email]).first

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
          resource = resource.pam_on_filled_pw(attributes) unless resource.password.blank?

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

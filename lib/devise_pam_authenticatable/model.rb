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

      def self.required_fields(klass)
        []
      end

      # Set password to nil
      def clean_up_passwords
        self.password = nil
      end

      def get_service
        if self.class.instance_variable_defined?("@pam_service")
          return self.class.pam_service
        else
          return ::Devise::pam_default_service
        end
      end

      def pam_setup(attributes)
        return unless ::Devise::emailfield
        self[::Devise::emailfield] = Rpam2.getenv(get_service, get_pam_name, attributes[:password], "email", false)
      end

      def password_required?
        return false if Rpam2.account(get_service, get_pam_name)
        super
      end

      def get_suffix
        return self.class.pam_suffix if self.class.instance_variable_defined?("@pam_suffix")
        ::Devise::pam_default_suffix
      end

      def get_pam_name
        return self[::Devise::usernamefield] if ::Devise::usernamefield && \
                                                has_attribute?(::Devise::usernamefield) && \
                                                attribute_present?(::Devise::usernamefield)
        suffix = get_suffix()
        return nil unless suffix && has_attribute?(::Devise::emailfield)
        email = "#{self[::Devise::emailfield]}\n"
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

        def authenticate_with_pam(attributes={})
          if ::Devise::usernamefield && attributes[::Devise::usernamefield].present?
            resource = where(::Devise::usernamefield => attributes[::Devise::usernamefield]).first

            if resource.blank?
              resource = new
              resource[::Devise::usernamefield] = attributes[::Devise::usernamefield]
            end
          elsif attributes[::Devise::emailfield].present?
            resource = where(::Devise::emailfield => attributes[::Devise::emailfield]).first

            if resource.blank?
              resource = new
              resource[::Devise::emailfield] = attributes[::Devise::emailfield]
            end
          else
            return nil
          end

          if resource.try(:valid_pam_authentication?, attributes[:password])
            resource.pam_setup(attributes)
            resource.save if resource.new_record?
            return resource
          else
            return nil
          end
        end
      end
    end
  end
end

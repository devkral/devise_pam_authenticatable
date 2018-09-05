require 'devise/strategies/base'


class Devise::Strategies::PamAuthenticatable < Devise::Strategies::Authenticatable
  def valid?
    super && (::Devise.emailfield || ::Devise.usernamefield)
  end

  def authenticate!
    pam_params = params[scope].clone
    pam_params[:request] = request
    if (resource = mapping.to.authenticate_with_pam(pam_params))
      success!(resource)
    else
      fail(:invalid)
    end
  end
end

Warden::Strategies.add(:pam_authenticatable, Devise::Strategies::PamAuthenticatable)

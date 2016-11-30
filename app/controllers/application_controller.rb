class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :block_foreign_hosts, if: :devise_controller?

  def whitelisted?(ip)
    return true if ['103.43.128.42', '114.110.18.14'].include?(ip)
    # return true if ['114.110.18.14'].include?(ip)
    false
  end

  def block_foreign_hosts
    return false if whitelisted?(request.remote_ip)
    redirect_to "https://www.google.com"
  end


end

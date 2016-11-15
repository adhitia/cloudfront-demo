class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :block_foreign_hosts

  def whitelisted?(ip)
    return true if ['103.43.128.42'].include?(ip)
    false
  end

  def block_foreign_hosts
    return false if whitelisted?(request.remote_ip)
    redirect_to "https://www.google.com"
  end


end

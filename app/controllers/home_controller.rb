class HomeController < ApplicationController
  def index
    redirect_to get_ticket_path({:service => ENV['CONTENT_URL']}) and return
  end
end

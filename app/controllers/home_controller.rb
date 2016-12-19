class HomeController < ApplicationController
  def index
    redirect_to get_ticket_path and return
  end
end

class AddContentSiteUrlToUsers < ActiveRecord::Migration
  def change
    add_column :users, :content_site_url, :string
  end
end

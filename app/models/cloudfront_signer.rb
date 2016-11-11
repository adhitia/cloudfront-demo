class CloudfrontSigner
  class << self
    #
    # Returns a hash of cookie name / values to set.
    #
    # It expects as arguments the resource to protect and when the policy should expire
    # 
    # The policy method could be extended to support the other condtions Cloudfront supports (eg ip address)
    def cookie_data(resource, expiry)
      raw_policy = policy(resource, expiry)
      {
        'CloudFront-Policy' => safe_base64(raw_policy),
        'CloudFront-Signature' => sign(raw_policy),
        'CloudFront-Key-Pair-Id' => 'APKAJKBYQFZ6L76RLPAA'
      }
    end

    private

    def policy(url, expiry)
      {
         "Statement"=> [
            {
               "Resource" => url,
               "Condition"=>{
                  "DateLessThan" =>{"AWS:EpochTime"=> expiry.utc.to_i}
               }
            }
         ]
      }.to_json.gsub(/\s+/,'')
    end

    def safe_base64(data)
      Base64.strict_encode64(data).tr('+=/', '-_~')
    end

    def sign(data)
      private_key = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAjfsTD7wEvTm9mV2LN14ABy62yXN9xAL3SyGC9/KzLWiWTPNnAVUcxb0dOOGr2O+XccSdtUdjqCSE4MIYT6PVRfXIDHx8uNH7D8QrA4V9qgmZ0pr5Ggp2IKZxJdE/poNBUquddOUCnn171ovS+XjpZElfDgBXl89Vx2A/Sk8vuUQIrMfKI8Wvc26seN9trWxPeH3Mpf6JjXFEfrSIoBzNdBd3CWgoGw7WWJwEQbuRAO/4eoFQWjTOHUPav9YJwTl9CcKRyzX0oEDaTS9lRQKeolxYDtFvUv7UvgoAgrU/Ke34vKp8FWBZBHPQ/3a7EMLhYcwbJIS/slmNq9FYzGzr0QIDAQABAoIBAHg7Z/bpF3JOlTpsttnaJlfuvSd3P8dfY58h79CcnBMWAEGF1XKRat4gucBTir0Yl7zl7U939vKKimPyubenW5H1AsVgHhY860h8rJg80R/PJY3tYokk1sfrauHFgws1F3o0jhBRZphkVxxmJ/DO7YXZhD9NFuAd2dwOq0n4KMfPhO4QrVpe0sSjg1Y1NqLXGAtu+mc6gL6cxWAHe9U05cvsLHMu/XYLBpSRIGQtB/Ri9mExXJUf+6KFcR6YfSmhpGovd4jwq7WA7H8pe+QadsA9b66va6hFUzZn4Hv4ekw5QB8VmPFebz4qF6CuFhHicb3r1xppU61+2kLWVbbSgIECgYEA6/QMrQU/7/qeJ1+8YS19dEHaji0DDThqETOeY9H2///dEnQ8d1G3rNsJzwFjLfgWDZliJIAq9bL0WTXZLHZg4ZCkWqGWmtm/ZZiXnjOXgbteGJwXsgIk1y0oHTtRNymivljj6a58tIngljSYQMkfy705I/eHjrJGNDJ2Pab12PkCgYEAmgsiqgHSKHFb5lY8OLL6sqVukR064kKbX0I1Ig/lFKTUFsb9w0UNjsVDqD3uStawCgYumPNvDjKs7PhwHHfrIcxL0/L1yC1GheRrEy5IlkCGvYYooQ8yqz9emqDYtwG51OqSU9IMBRrC9FVT2dj3AtuiVv3Aj4WFVRfk86fW95kCgYAzZApGvPf6CrnblYxwFfpXEejKQp+Bh6ICcR20XAzSISZDWLG6wz+gFG0Eeybg4kHbYGbx0ECLFxkFPSc5+eaL+nbxjnRA8eAv/pY3TMFY7jhGX+kBSlo/y4QLKdo8i4L4tl+di/V5VPZngLkQkz2roGELpmQN/mIwCDWco/qz8QKBgHq3XkETPEmtrOl9T3JX2vHQapm+MHepWj9z7gIZqYRdnvwaQHR8IUXYjoKL+7aw+wKxVBPS8mjcI/iQHjf/rFh7ePj7N6PltaXahxZ7q6XO98gqBVnxUosr64DBnIOGI3Wj/Tg7QAoc/KxLAYatmnIzaEtm0S1E0Cgu5dzZm54ZAoGBANHiAKjEWVzMttbVlFfXT+Zyu+wVD9tkR54VlOopSFIvZeUqwkvYVehIzOOYv8Mb4PPxTs3XpKhsm2zQbmwM7666Gs/fF5jVXKQuRp3dyPthKsGgPNL6k441vUT3cj9GWgApwNHqN6k9LkXTsHUwlvCvpmTjfgKnV35i3y35xwCx-----END RSA PRIVATE KEY-----"
      digest = OpenSSL::Digest::SHA1.new
      key    = OpenSSL::PKey::RSA.new private_key
      result = key.sign digest, data
      safe_base64(result)
    end
  end
end
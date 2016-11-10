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
        'CloudFront-Key-Pair-Id' => 'APKAJFDBD2J2ZLXM32TA'
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
      private_key = "-----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAjhUQFSDxNvwby+8u7vgH/76Utr1teEi23i78vdW20P705Zm5
        NDA6VEb5Cca6vE2P6hmBmGQrmQkcOkKfp1B8PQM2HmcLpsENSTnrKWtXpwrK1stB
        VQcYcAyFALyFuCkudO0iSwAL7ZXjMAWpMuxkcj+wOHV4RrdnAObAUI9MwYTteghI
        Kkv+krG0BboJyuj013icY1U/yGH+ROZxrzxdDh9xNg7DtzZmPFWL2quBDLW1D5+A
        BUcB/7zcgMdhlbnaBInbL5agLi8xHx8XYUhmz6akNyCqX9rEmdi8UvY7758msblQ
        /pJM21NknDILlUprkknbg43zsuabmzjNe1KS+wIDAQABAoIBAEaZCKi2+aRMmLM4
        YaWz8KWO2O4EKcS+vL6hskvRSUmHpcAAJhpcbF879Lp62IaAM6Yqjk5eV5tu/2uj
        dxj30QOv+NAae5ucCTH9aW/nOmJx5l/cFtZc9DOYxO2cvwTG0aKfwY5qs4KWG5Dc
        /zmiZDawlqs3E1BwCOpVvfFJguYUmt1MlFRNMSJnvAD1pjpGdGBXf6NIJkCf4yWL
        9kZwVRuBf3GX/RqMFSaSYSqdrI7JF4pL0EBODAdbP0lu9fGM2ruhFXuLU302wrwG
        lylSRzBfSfLX5VLZR20i179IPSZmqkDKhohPzjOVG5KgjoHGbIiNTD8TQbszM9Ph
        2+GXf0ECgYEA3xv+VuevyRhni+f96Dl+shohS9tiF1MCT6ZQSD4Ny0ZEJFR4YfD0
        aS8h8s7QUBTR/OM6s8Ap9WW9JKfU+aj7CWcOBZ8CcxYOzU9E+eUL1w1jJh4RGUl4
        mAlLQ/tHC3jySmH41uyeMyYvGfbuInv/jDUC0Cq98DIx16qzNY/eaAkCgYEAowco
        ltjAdF9VdU9f8EL75Ys3rieaB1cLEDdDRbFntcGD+9I3BGRblnRg+eQ2U96YGwMk
        WHRLpjP+mMYP0AmnSo7c5gmTZclma4aSrUGMJZO8YiA3SAx9MxYdzJm4dmDSZtWc
        QbJvMNtCbFuGIFy0cwKi7C5lZ/vvSyndnKwge+MCgYEAij4uOmsU4OXeQzJcgage
        ePz35Kjq/sjQhcnntNu+cFX5owk0Dnve9c3emzTKntRHyQqDNR284fFIYY4cyRWL
        dygD6De+rNDeGxkjBDSIQZhp9xRqQ+DieFJJ8LWiL9mhR7WtGn9DBy6BwPTgWT27
        +oReWd4iEtMHTzrWEDo09QECgYBA9Jk3gSUtOM7T7sxK7mVvEAkfWqgERKojy+EB
        461uvavYqelB1rqnN7dr2YHL6OSx3o6cr7l0f0Lxm/iw6ye8jS92eFpCM/ya2wOW
        BIfScQqeDjf4fQFlWWqGGrlkcS9jybh4dJ/Y14OfqNfIDSfYqzQ+5j2BMOAnEoc5
        5VsMAQKBgAVtkhvjuiNv2LfwVUT3FL7sa1pXj4xFra8CKhKPv3T/RnREPx6xZ0Cr
        /wYKs/Qh/SVWs56PB2+ZxR5IwE6TWCGO9y98z6I3jmYqIDUbEinMiWHMVVAHfCHe
        qhsMSYAe9nR4DQk+6OzW7VeUSrPlf0GH4H3E6eqfDjbDyADiRkXI
        -----END RSA PRIVATE KEY-----"

      digest = OpenSSL::Digest::SHA1.new
      key    = OpenSSL::PKey::RSA.new private_key
      result = key.sign digest, data
      safe_base64(result)
    end
  end
end
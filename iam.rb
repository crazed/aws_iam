require 'cgi'
require 'uri'
require 'openssl'
require 'digest/sha1'
require 'net/https'
require 'time'
require 'rexml/document'

module AWS
  class IAM
    def initialize(access_key_id, secret_access_key)
      @host = 'iam.amazonaws.com'
      @uri = '/'
      @access_key_id = access_key_id
      @secret_access_key = secret_access_key
    end

    def list_users
      @params = {
        'Action' => 'ListUsers'     
      }
      add_default_params
      doc = send_request
      doc.elements.each('ListUsersResponse/ListUsersResult/Users/member/UserName') do |user|
        puts user.text
      end
    end


    private
      def send_request(method = :get)
        http = create_connection
        case method
        when :get
          @method = "GET"
          path = "/?#{cannonical_string}&Signature=#{signature}"
          response, xml_data = http.get(path)
          return REXML::Document.new(xml_data)
        end
      end

      def add_default_params
        @params['Timestamp'] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        @params['AWSAccessKeyId'] = @access_key_id
        @params['Version'] = '2010-05-08'
        @params['SignatureVersion'] = '2'
        @params['SignatureMethod'] = 'HmacSHA256'
      end

      def cannonical_string
        # sort the hash by key value and return by creating an array
        param_array = Array.new
        @params.sort_by { |k, v| k }.each do |param|
          param_array << "#{param[0]}=#{CGI.escape param[1]}"
        end

        # create the canonical_string
        canonical_string = "#{param_array.join('&')}"
      end

      def string_to_sign
       return "#{@method}\n#{@host}\n#{@uri}\n#{cannonical_string}"
      end

      def signature
        digest = OpenSSL::Digest::Digest.new('sha256')
        b64_hmac = [OpenSSL::HMAC.digest(digest, @secret_access_key, string_to_sign)].pack("m").strip
        CGI.escape(b64_hmac)
      end

      def create_connection
        http = Net::HTTP.new(@host, 443)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http
      end
  end
end

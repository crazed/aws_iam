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

    def get_users
      params = {
        'Action' => 'ListUsers'     
      }
      doc = make_document(send_request(params))
      users = Array.new
      doc.elements.each('//UserName') do |user|
        users << user.text
      end

      return users
    end

    def create_user(username, path='/')
      params = {
        'Action'    => 'CreateUser',
        'Path'      => path,
        'UserName'  => username
      }
      send_request(params)
    end

    def get_signing_certificates(username)
      params = {
        'Action'    => 'ListSigningCertificates',
        'UserName'  => username
      }
      certificates = Array.new
      doc = make_document(send_request(params))
      doc.elements.each('//CertificateId') do |cert_id|
        certificates << cert_id.text
      end
      certificates
    end

    def get_access_keys(username)
      params = {
        'Action'    => 'ListAccessKeys',
        'UserName'  => username
      }
      access_keys = Array.new
      doc = make_document(send_request(params))
      doc.elements.each('//AccessKeyId') do |access_key_id|
        access_keys << access_key_id.text
      end
      access_keys
    end

    def get_groups_for_user(username)
      params = {
        'Action'    => 'ListGroupsForUser',
        'UserName'  => username
      }
      groups = Array.new
      doc = make_document(send_request(params))
      doc.elements.each('//GroupName') do |group|
        groups << group.text
      end
      groups
    end

    def get_groups(path='/')
      params = {
        'Action'      => 'ListGroups',
        'PathPrefix'  => path
      }
      groups = Array.new
      doc = make_document(send_request(params))
      doc.elements.each('//GroupName') do |group|
        groups << group.text
      end
      groups
    end

    def delete_user(username)
      params = {
        'Action'    => 'DeleteUser',
        'UserName'  =>  username
      }

      get_signing_certificates(username).each do |cert_id|
        delete_signing_certificate(cert_id, username)
      end

      get_groups_for_user(username).each do |group|
        remove_user_from_group(username, group)
      end

      get_access_keys(username).each do |access_key_id|
        delete_access_key(access_key_id, username)
      end

      send_request(params)
    end

    def delete_signing_certificate(cert_id, username=nil)
      params = {
        'Action'        => 'DeleteSigningCertificate',
        'CertificateId' => cert_id
      }
      params['UserName'] = username if username
      send_request(params)
    end

    def delete_access_key(access_key_id, username=nil)
      params = {
        'Action'      => 'DeleteAccessKey',
        'AccessKeyId' => access_key_id
      }
      params['UserName'] = username if username
      send_request(params)
    end

    def remove_user_from_group(username, group)
      params = {
        'Action'        => 'RemoveUserFromGroup',
        'UserName'      => username,
        'GroupName'     => group
      }
      send_request(params)
    end

    def create_access_key(username=nil)
      params = {
        'Action'    => 'CreateAccessKey',
      }
      params['UserName'] = username if username
      doc = make_document(send_request(params))
      
      iam_credentials = Hash.new
      doc.elements.each('//AccessKeyId') do |access_key_id|
        iam_credentials[:access_key_id] = access_key_id.text
      end

      doc.elements.each('//SecretAccessKey') do |secret_access_key|
        iam_credentials[:secret_access_key] = secret_access_key.text
      end
      
      iam_credentials
    end

    def upload_signing_certificate(certificate, username=nil)
      params = {
        'Action'          => 'UploadSigningCertificate',
        'CertificateBody' => certificate
      }
      params['UserName'] = username if username
      send_request(params, :post)
    end


    private
      def send_request(params, method = :get)
        params.merge! add_default_params
        http = create_connection
        case method
        when :get
          @method = "GET"
          path = get_path(params)
          response, xml_data = http.get("#{@uri}?#{path}")
        when :post
          @method = "POST"
          path = get_path(params)
          response, xml_data = http.post(@uri, path)
        else
          raise Exception.new("send_request called without a valid method: #{method}")
        end

        case response
        when Net::HTTPOK
          return xml_data
        else
          # find the error message and return it
          root = make_document(xml_data).root
          code = root.elements["Error[1]/Code"].text
          msg = root.elements["Error[1]/Message"].text
          raise Exception.new("#{code}: #{msg}")
        end
      end

      def make_document(xml_data)
        return REXML::Document.new(xml_data)
      end

      def add_default_params
        {
          'Timestamp'         => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
          'AWSAccessKeyId'    => @access_key_id,
          'Version'           => '2010-05-08',
          'SignatureVersion'  => '2',
          'SignatureMethod'   => 'HmacSHA256'
        }
      end

      def get_path(params)
        # first we need to get the canonical string
        # this needs to be sorted alphabetically
        param_array = Array.new
        params.sort_by { |k, v| k}.each do |param|
          param_array << "#{CGI.escape(param[0]).gsub("+", "%20")}=#{CGI.escape(param[1]).gsub("+", "%20")}"
        end
        canonical_string = "#{param_array.join('&')}"

        # make the string to sign and sign it
        string_to_sign = "#{@method}\n#{@host}\n#{@uri}\n#{canonical_string}"
        digest = OpenSSL::Digest::Digest.new('sha256')
        b64_hmac = [OpenSSL::HMAC.digest(digest, @secret_access_key, string_to_sign)].pack("m").strip
        signature = CGI.escape(b64_hmac)
        #return "#{@uri}?#{canonical_string}&Signature=#{signature}"
        return "#{canonical_string}&Signature=#{signature}"
      end

      def create_connection
        http = Net::HTTP.new(@host, 443)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http
      end
  end
end

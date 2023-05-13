from datetime import datetime
import xml.etree.ElementTree as ET
import urllib.parse
import zlib
import binascii

domain = "gedu.demo.calriz.com"
issuer = "google.com"
realm = "rnp-intbr"
url_idp = f"https://auth.dev.idp.fit/realms/{realm}/protocol/saml"

current_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

xml_string = f'''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="kpinfagbbddbophbdfchlfekeibhgjlcjahlppbf"
                    Version="2.0"
                    IssueInstant="{current_time}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    ProviderName="google.com"
                    IsPassive="false"
                    AssertionConsumerServiceURL="https://www.google.com/a/{domain}/acs"
                    >
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>
            <samlp:NameIDPolicy AllowCreate="true"
                                Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                                />
</samlp:AuthnRequest>'''


root = ET.fromstring(xml_string)

# Convert the XML to a string representation
xml_str = ET.tostring(root, encoding='utf-8', method='xml')

def b64encode(s, altchars=None):
    """Encode the bytes-like object s using Base64 and return a bytes object.

    Optional altchars should be a byte string of length 2 which specifies an
    alternative alphabet for the '+' and '/' characters.  This allows an
    application to e.g. generate url or filesystem safe Base64 strings.
    """
    encoded = binascii.b2a_base64(s, newline=False)
    if altchars is not None:
        assert len(altchars) == 2, repr(altchars)
        return encoded.translate(bytes.maketrans(b'+/', altchars))
    return encoded

def b64_deflate(string_val):
    cmp_str = zlib.compress(string_val)[2:-4]
    return b64encode(cmp_str)

saml_request = urllib.parse.quote(b64_deflate(xml_str))

state = "https://accounts.google.com/CheckCookie?continue=https%3A%2F%2Faccounts.google.com%2Fo%2Foauth2%2Fv2%2Fauth%3Fresponse_type%3Dtoken%26client_id%3D498559821111-t7o0pm6psh5b3idofaeprkd79cd8r9ns.apps.googleusercontent.com%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A3000%252Flooker-access%26scope%3Demail%26hd%3Dgedu.demo.calriz.com%26authuser%3Dunknown&client_id=498559821111-t7o0pm6psh5b3idofaeprkd79cd8r9ns.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Flooker-access&scope=email"
print(f"{url_idp}?SAMLRequest={saml_request}&RelayState={state}")


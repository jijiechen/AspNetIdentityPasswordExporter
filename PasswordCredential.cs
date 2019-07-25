

namespace AspNetIdentityPasswordExporter
{
  class PasswordCredential
  {
    public string type => "password";

    public string algorithm { get; set;}
    public int hashIterations {get;set;}
    public string hashedSaltedValue {get;set;}
    public string salt {get;set;}




    public const string Pbkdf2SHA1 = "pbkdf2";
    public const string Pbkdf2SHA256 = "pbkdf2-sha256";
    public const string Pbkdf2SHA512 = "pbkdf2-sha512";
  }

}
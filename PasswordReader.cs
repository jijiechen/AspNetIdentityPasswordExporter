using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;

namespace AspNetIdentityPasswordExporter
{
  class PasswordReader
  {

  // ASP.NET Core Identity Password Hasher
  // https://github.com/aspnet/AspNetCore/blob/master/src/Identity/Extensions.Core/src/PasswordHasher.cs

    public static PasswordCredential ReadPassword(string hashedPassword)
    {
      if (hashedPassword == null)
        throw new ArgumentNullException(nameof (hashedPassword));
      byte[] hashedBytes = Convert.FromBase64String(hashedPassword);
      if (hashedBytes.Length == 0)
        return null;


    if(hashedBytes[0] == 0){
        return ReadIdentityV2Password(hashedBytes);
    }

      try
      {
        var prfByte = ReadNetworkByteOrder(hashedBytes, 1);
        int iterCount = (int) ReadNetworkByteOrder(hashedBytes, 5);

        int saltLength = (int) ReadNetworkByteOrder(hashedBytes, 9);
        if (saltLength < 16)
          return null;

        byte[] salt = new byte[saltLength];
        Buffer.BlockCopy((Array) hashedBytes, 13, (Array) salt, 0, salt.Length);
        int numBytesRequested = hashedBytes.Length - 13 - salt.Length;
        if (numBytesRequested < 16)
          return null;
        
        byte[] password = new byte[numBytesRequested];
        Buffer.BlockCopy((Array) hashedBytes, 13 + salt.Length, (Array) password, 0, password.Length);
        
        return new PasswordCredential{
            algorithm = KeyCloakAlgorithmId(prfByte),
            hashIterations = iterCount,
            hashedSaltedValue = Convert.ToBase64String(password),
            salt = Convert.ToBase64String(salt)
        };
      }
      catch
      {
        return null;
      }
    }

    private static PasswordCredential ReadIdentityV2Password(byte[] hashedBytes)
    {
      if (hashedBytes.Length != 49)
        return null;

      byte[] salt = new byte[16];
      Buffer.BlockCopy((Array) hashedBytes, 1, (Array) salt, 0, salt.Length);

      byte[] password = new byte[32];
      Buffer.BlockCopy((Array) hashedBytes, 1 + salt.Length, (Array) password, 0, password.Length);
      
      return new PasswordCredential{
          algorithm = PasswordCredential.Pbkdf2SHA1,
          hashIterations = 1000,
          hashedSaltedValue = Convert.ToBase64String(password),
          salt = Convert.ToBase64String(salt)
      };
    }

    private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
    {
      return (uint) ((int) buffer[offset] << 24 | (int) buffer[offset + 1] << 16 | (int) buffer[offset + 2] << 8) | (uint) buffer[offset + 3];
    }

    private static string KeyCloakAlgorithmId(uint prfByte){
        var prf = (KeyDerivationPrf) prfByte;
        switch (prf){
            case KeyDerivationPrf.HMACSHA256:
                return PasswordCredential.Pbkdf2SHA256;
            case KeyDerivationPrf.HMACSHA512:
                return PasswordCredential.Pbkdf2SHA512;
            default:
                return PasswordCredential.Pbkdf2SHA1;
        }
    }

  }
}

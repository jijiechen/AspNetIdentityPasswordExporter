using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace AspNetIdentityPasswordExporter
{
  class PasswordReader
  {
    private readonly CompatibilityMode _compatibilityMode;
    private readonly int _iterCount;
    private readonly RandomNumberGenerator _rng;

    public virtual string HashPassword(string password)
    {
      if (password == null)
        throw new ArgumentNullException(nameof (password));
      if (this._compatibilityMode == CompatibilityMode.IdentityV2)
        return Convert.ToBase64String(HashPasswordV2(password, this._rng));
      return Convert.ToBase64String(this.HashPasswordV3(password, this._rng));
    }

    private static byte[] HashPasswordV2(string password, RandomNumberGenerator rng)
    {
      byte[] numArray1 = new byte[16];
      rng.GetBytes(numArray1);
      byte[] numArray2 = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(password, numArray1, KeyDerivationPrf.HMACSHA1, 1000, 32);
      byte[] numArray3 = new byte[49];
      numArray3[0] = (byte) 0;
      Buffer.BlockCopy((Array) numArray1, 0, (Array) numArray3, 1, 16);
      byte[] numArray4 = numArray3;
      Buffer.BlockCopy((Array) numArray2, 0, (Array) numArray4, 17, 32);
      return numArray3;
    }

    private byte[] HashPasswordV3(string password, RandomNumberGenerator rng)
    {
      return HashPasswordV3(password, rng, KeyDerivationPrf.HMACSHA256, this._iterCount, 16, 32);
    }

    private static byte[] HashPasswordV3(
      string password,
      RandomNumberGenerator rng,
      KeyDerivationPrf prf,
      int iterCount,
      int saltSize,
      int numBytesRequested)
    {
      byte[] numArray1 = new byte[saltSize];
      rng.GetBytes(numArray1);
      byte[] numArray2 = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(password, numArray1, prf, iterCount, numBytesRequested);
      byte[] buffer = new byte[13 + numArray1.Length + numArray2.Length];
      buffer[0] = (byte) 1;
      WriteNetworkByteOrder(buffer, 1, (uint) prf);
      WriteNetworkByteOrder(buffer, 5, (uint) iterCount);
      WriteNetworkByteOrder(buffer, 9, (uint) saltSize);
      Buffer.BlockCopy((Array) numArray1, 0, (Array) buffer, 13, numArray1.Length);
      Buffer.BlockCopy((Array) numArray2, 0, (Array) buffer, 13 + saltSize, numArray2.Length);
      return buffer;
    }



    public PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
    {
      if (hashedPassword == null)
        throw new ArgumentNullException(nameof (hashedPassword));
      if (providedPassword == null)
        throw new ArgumentNullException(nameof (providedPassword));
      byte[] hashedPassword1 = Convert.FromBase64String(hashedPassword);
      if (hashedPassword1.Length == 0)
        return PasswordVerificationResult.Failed;
      switch (hashedPassword1[0])
      {
        case 0:
          if (!VerifyHashedPasswordV2(hashedPassword1, providedPassword))
            return PasswordVerificationResult.Failed;
          return this._compatibilityMode != CompatibilityMode.IdentityV3 ? PasswordVerificationResult.Success : PasswordVerificationResult.SuccessRehashNeeded;
        case 1:
          int iterCount;
          if (!VerifyHashedPasswordV3(hashedPassword1, providedPassword, out iterCount))
            return PasswordVerificationResult.Failed;
          return iterCount >= this._iterCount ? PasswordVerificationResult.Success : PasswordVerificationResult.SuccessRehashNeeded;
        default:
          return PasswordVerificationResult.Failed;
      }
    }

    private static bool VerifyHashedPasswordV2(byte[] hashedPassword, string password)
    {
      if (hashedPassword.Length != 49)
        return false;
      byte[] salt = new byte[16];
      Buffer.BlockCopy((Array) hashedPassword, 1, (Array) salt, 0, salt.Length);
      byte[] b = new byte[32];
      Buffer.BlockCopy((Array) hashedPassword, 1 + salt.Length, (Array) b, 0, b.Length);
      return ByteArraysEqual(Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA1, 1000, 32), b);
    }

    private static bool VerifyHashedPasswordV3(
      byte[] hashedPassword,
      string password,
      out int iterCount)
    {
      iterCount = 0;
      try
      {
        KeyDerivationPrf prf = (KeyDerivationPrf) ReadNetworkByteOrder(hashedPassword, 1);
        iterCount = (int) ReadNetworkByteOrder(hashedPassword, 5);
        int length = (int) ReadNetworkByteOrder(hashedPassword, 9);
        if (length < 16)
          return false;
        byte[] salt = new byte[length];
        Buffer.BlockCopy((Array) hashedPassword, 13, (Array) salt, 0, salt.Length);
        int numBytesRequested = hashedPassword.Length - 13 - salt.Length;
        if (numBytesRequested < 16)
          return false;
        byte[] b = new byte[numBytesRequested];
        Buffer.BlockCopy((Array) hashedPassword, 13 + salt.Length, (Array) b, 0, b.Length);
        return ByteArraysEqual(Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(password, salt, prf, iterCount, numBytesRequested), b);
      }
      catch
      {
        return false;
      }
    }


    private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
    {
      return (uint) ((int) buffer[offset] << 24 | (int) buffer[offset + 1] << 16 | (int) buffer[offset + 2] << 8) | (uint) buffer[offset + 3];
    }


    private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
    {
      buffer[offset] = (byte) (value >> 24);
      buffer[offset + 1] = (byte) (value >> 16);
      buffer[offset + 2] = (byte) (value >> 8);
      buffer[offset + 3] = (byte) value;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
      if (a == null && b == null)
        return true;
      if (a == null || b == null || a.Length != b.Length)
        return false;
      bool flag = true;
      for (int index = 0; index < a.Length; ++index)
        flag &= (int) a[index] == (int) b[index];
      return flag;
    }
  }
}

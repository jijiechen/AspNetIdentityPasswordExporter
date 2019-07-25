using System;

namespace AspNetIdentityPasswordExporter
{
    class PasswordVerificationResult
    {
        private bool _isSuccess;
        public bool IsSuccess => this._isSuccess;

        public static PasswordVerificationResult Failed = new PasswordVerificationResult{ _isSuccess = false };
        public static PasswordVerificationResult Success = new PasswordVerificationResult{ _isSuccess = true };
        public static PasswordVerificationResult SuccessRehashNeeded = new PasswordVerificationResult{ _isSuccess = true };











        
    }
}

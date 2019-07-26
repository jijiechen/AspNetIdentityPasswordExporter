
using System.Collections.Generic;

namespace AspNetIdentityPasswordExporter
{
  class ExportedUser {
      public string username {get;set;}
      public bool enabled => true;


      private List<PasswordCredential> _creds = new List<PasswordCredential>();
      public List<PasswordCredential> credentials => _creds;
      public List<string> realmRoles => new List<string>();
  }

}
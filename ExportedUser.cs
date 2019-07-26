
using System.Collections.Generic;

namespace AspNetIdentityPasswordExporter
{
  class ExportedUser {
      public string username {get;set;}
      public bool enabled => true;
      public List<PasswordCredential> credentials => new List<PasswordCredential>();
      public List<string> realmRoles => new List<string>();
  }

}
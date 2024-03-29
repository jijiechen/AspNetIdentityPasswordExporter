﻿using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace AspNetIdentityPasswordExporter
{
    class Program
    {
        static void Main(string[] args)
        {

            var users = new List<IdentityUser>();
            
            var dbString = "";
            using (var connection = new SqliteConnection(dbString))
            {
                connection.Open();
                using(var command = new SqliteCommand("select UserName,HashedPassword from User order by Id asc", connection)){
                    using(var reader = command.ExecuteReader()){
                        while(reader.Read()){
                            var identityUser = new IdentityUser();
                            identityUser.UserName = ConvertFromDBVal<string>(reader["UserName"]);
                            identityUser.HashedPassword = ConvertFromDBVal<string>(reader["HashedPassword"]);

                            if(identityUser.UserName != null && identityUser.HashedPassword != null){
                                users.Add(identityUser);
                            }
                        }
                    }
                }
            }

            var allExportedUsers = users.Select(ExportUser).ToArray();
            Console.WriteLine(JsonConvert.SerializeObject(allExportedUsers));
        }


        static ExportedUser ExportUser(IdentityUser user){
            var exported = new ExportedUser{
                username = user.UserName
            };

            var credential = PasswordReader.ReadPassword(user.HashedPassword);
            exported.credentials.Add(credential);
            return exported;
        }


      static T ConvertFromDBVal<T>(object obj)
        {
            if (obj == null || obj == DBNull.Value)
            {
                return default(T); // returns the default value for the type
            }
            else
            {
                return (T)obj;
            }
        }










        
    }
}

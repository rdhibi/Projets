using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using WebApiApp.Helpers;
using WebApiApp.Models;

namespace WebApiApp.Controllers
{
    /// <summary>
    /// classe d'identification
    /// </summary>
    public class IdentityController : ApiController
    {
        #region Api

        /// <summary>
        /// authentication via email et passwort
        /// </summary>
        /// <param name="email">email</param>
        /// <param name="password">mot de passe</param>
        /// <returns></returns>
        [Route("api/authenticate/{email}/{password}")]
        [System.Web.Http.HttpGet]
        public bool Authenticate(string email, string password)
        {
            if (!Users.Any()) return false;

            var userList = Users.Where(u => Login(u, email, password)).ToList();

            return userList != null && userList.Any();
        }


        /// <summary>
        /// vérif accès non sécurisé
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Route("api/confidentials/{email}")]
        [System.Web.Http.HttpGet]
        public bool Confidentials(string email)
        {
            return GetConfidentials(email);
        }

        /// <summary>
        /// vérif accès avec autorisation
        /// </summary>
        /// <param name="email"></param>
        /// <returns>retourne si accès autorisé</returns>
        [AuthorizationAttribute]
        [Route("api/ConfidentialsWithAuthorization/{email}")]
        [System.Web.Http.HttpGet]
        public bool ConfidentialsWithAuthorization(string email)
        {
            return GetConfidentials(email);
        }

        /// <summary>
        /// vérif accès
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        private bool GetConfidentials(string email)
        {
            if (!UsersLoged.Any()) return false;

            var userList = UsersLoged.Where(u => Loged(u, email, "")).ToList();

            return userList != null && userList.Any();
        }

        #endregion

        #region acess
        /// <summary>
        /// données
        /// </summary>
        User[] Users = new User[]
        {
            new User { Email = "user1@test.com", Password = "user1" },
            new User { Email = "user2@test.com", Password = "user2" },
            new User { Email = "user3@test.com", Password = "user3" },
        };

        User[] UsersLoged = new User[]
        {
            new User { Email = "user1@test.com", Password = "user1" }
        };

        /// <summary>
        /// déligué pour créer des filtres
        /// </summary>
        /// <param name="u"></param>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public delegate bool UserLogin(User u, string email, string password);
        public static UserLogin Login = (u, email, password) =>
        {
            return u != null && !string.IsNullOrEmpty(u.Email) && !string.IsNullOrEmpty(u.Password)
                && u.Email.Equals(email) && u.Password.Equals(password); ;
        };
        public static UserLogin Loged = (myUser, email, password) =>
        {
            return myUser != null && !string.IsNullOrEmpty(myUser.Email)
                && myUser.Email.Equals(email);
        };
        #endregion

    }
}

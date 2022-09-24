namespace CsVmomi
{
    using System.Globalization;
    using System.Linq;
    using System.Threading.Tasks;
    using VimService;

    public partial class SessionManager : ManagedObject
    {
        public async System.Threading.Tasks.Task<UserSession> Login(string userName, string password)
        {
            var supported = await this.GetPropertySupportedLocaleList();
            var locale = supported.FirstOrDefault(this.IsCurrentLocaleName);
            if (locale == null)
            {
                locale = supported.FirstOrDefault(this.IsCurrentLocaleTwoLetter);
            }

            return await this.Login(userName, password, locale);
        }

        private bool IsCurrentLocaleName(string locale)
        {
            var current = CultureInfo.CurrentUICulture.Name.Replace("-", "_");
            return locale.ToLowerInvariant() == current.ToLowerInvariant();
        }

        private bool IsCurrentLocaleTwoLetter(string locale)
        {
            var current = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
            return locale.ToLowerInvariant() == current.ToLowerInvariant();
        }
    }
}

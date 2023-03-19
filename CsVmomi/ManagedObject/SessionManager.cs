namespace CsVmomi;

using System.Globalization;

public partial class SessionManager : ManagedObject
{
    public async System.Threading.Tasks.Task<UserSession?> Login(string userName, string password)
    {
        var locale = await this.GetCurrentLocale();
        return await this.Login(userName, password, locale);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginByToken()
    {
        var locale = await this.GetCurrentLocale();
        return await this.LoginByToken(locale);
    }

    private async System.Threading.Tasks.Task<string?> GetCurrentLocale()
    {
        var supported = await this.GetPropertySupportedLocaleList();
        var locale = supported?.FirstOrDefault(this.IsCurrentLocaleName);
        if (locale == null)
        {
            locale = supported?.FirstOrDefault(this.IsCurrentLocaleTwoLetter);
        }

        return locale;
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

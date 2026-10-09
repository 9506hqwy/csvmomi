namespace CsVmomi;

using System.Globalization;

public partial class SessionManager : ManagedObject
{
    public async System.Threading.Tasks.Task<UserSession?> Login(string userName, string password)
    {
        var locale = await this.GetCurrentLocale().ConfigureAwait(false);
        return await this.Login(userName, password, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginByToken()
    {
        var locale = await this.GetCurrentLocale().ConfigureAwait(false);
        return await this.LoginByToken(locale).ConfigureAwait(false);
    }

    private async System.Threading.Tasks.Task<string?> GetCurrentLocale()
    {
        var supported = await this.GetPropertySupportedLocaleList().ConfigureAwait(false);
        var locale = supported?.FirstOrDefault(this.IsCurrentLocaleName);
        locale ??= supported?.FirstOrDefault(this.IsCurrentLocaleTwoLetter);

        return locale;
    }

    private bool IsCurrentLocaleName(string locale)
    {
#pragma warning disable CA1307
        var current = CultureInfo.CurrentUICulture.Name.Replace("-", "_");
#pragma warning restore CA1307
        return string.Equals(locale, current, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsCurrentLocaleTwoLetter(string locale)
    {
        var current = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        return string.Equals(locale, current, StringComparison.OrdinalIgnoreCase);
    }
}

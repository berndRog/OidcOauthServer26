namespace BankingBlazorSsr.Utils;

public static class IbanGenerator {
   
   public static string CreateGermanIban(string bban) {
      // remove spaces
      bban = new string(bban.Where(char.IsDigit).ToArray());

      if (bban.Length != 18)
         throw new ArgumentException("German BBAN must be 18 digits");

      var country = "DE";
      var temp = bban + CountryToNumbers(country) + "00";

      var remainder = Mod97(temp);
      var check = 98 - remainder;

      return Format($"{country}{check:00}{bban}");
   }

   private static string CountryToNumbers(string country) {
      return string.Concat(country.Select(c => (c - 'A' + 10).ToString()));
   }

   private static int Mod97(string input) {
      int remainder = 0;
      foreach (var c in input)
         remainder = (remainder * 10 + (c - '0')) % 97;

      return remainder;
   }
   
   public static string Format(string iban) {
      if (string.IsNullOrWhiteSpace(iban))
         return iban;

      // remove existing spaces
      iban = new string(iban.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

      return string.Join(" ",
         Enumerable.Range(0, (iban.Length + 3) / 4)
            .Select(i => iban.Substring(i * 4, Math.Min(4, iban.Length - i * 4))));
   }

}
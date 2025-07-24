using System;
using System.ComponentModel;
using System.Reflection;

namespace Checkmarx.API.AST.Utils
{
    public static class EnumUtils
    {
        public static T GetEnumValueByDescription<T>(string description) where T : struct, Enum
        {
            if (string.IsNullOrWhiteSpace(description))
                throw new ArgumentNullException(nameof(description), "Enum description cannot be null or empty.");

            foreach (var field in typeof(T).GetFields())
            {
                if (Attribute.GetCustomAttribute(field, typeof(DescriptionAttribute)) is DescriptionAttribute attr)
                {
                    if (attr.Description.Equals(description, StringComparison.OrdinalIgnoreCase))
                        return (T)field.GetValue(null);
                }
                else
                {
                    if (field.Name.Equals(description, StringComparison.OrdinalIgnoreCase))
                        return (T)field.GetValue(null);
                }
            }

            throw new InvalidOperationException($"'{description}' is not a valid {typeof(T).Name}.");
        }
    }
}

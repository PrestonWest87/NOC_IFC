using System.Text;

namespace NocIfc.Application.Features.Settings;

internal static class CsvRecordParser
{
    public static List<List<string>> Read(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        var endedOnRecordSeparator = false;
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (quoted)
            {
                if (character == '"')
                {
                    if (index + 1 < text.Length && text[index + 1] == '"')
                    {
                        field.Append('"');
                        index++;
                    }
                    else
                    {
                        quoted = false;
                    }
                }
                else
                {
                    field.Append(character);
                }
                endedOnRecordSeparator = false;
                continue;
            }

            if (character == '"' && field.Length == 0)
            {
                quoted = true;
                endedOnRecordSeparator = false;
            }
            else if (character == ',')
            {
                row.Add(field.ToString());
                field.Clear();
                endedOnRecordSeparator = false;
            }
            else if (character is '\r' or '\n')
            {
                row.Add(field.ToString());
                field.Clear();
                rows.Add(row);
                row = [];
                if (character == '\r' && index + 1 < text.Length && text[index + 1] == '\n')
                {
                    index++;
                }
                endedOnRecordSeparator = true;
            }
            else
            {
                field.Append(character);
                endedOnRecordSeparator = false;
            }
        }
        if (quoted)
        {
            throw new ArgumentException("CSV could not be parsed: unexpected end of quoted field.");
        }
        if (!endedOnRecordSeparator || field.Length > 0 || row.Count > 0)
        {
            row.Add(field.ToString());
            rows.Add(row);
        }
        return rows;
    }
}

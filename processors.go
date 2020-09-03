package gonymizer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/icrowley/fake"
)

// All processors are designed to work "unseeded"
// Make sure something seeds the RNG before you call the top level process function.

// in order for the processor to "find" the functions it's got to
// 1. conform to ProcessorFunc
// 2. be in the processor map

// There are fancy ways for the reflection/runtime system to find functions
// that match certain text patters, like how the system finds TestX(*t.Testing) funcs
// but we dont' need that.  just put them in the map to make my life easy please.

// The number of times to check the input string for similarity to the output string. We want to keep this at a distance
// of 0.4 or higher. Please see: https://en.wikipedia.org/wiki/Jaro%E2%80%93Winkler_distance
//const jaroWinklerAttempts = 1000

// lookup string for random lowercase letters
const lowercaseSet = "abcdefghijklmnopqrstuvwxyz"

// lookup string for random uppercase letters
const uppercaseSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// lookup string for random integers
const numericSet = "0123456789"

const lowercaseSetLen = 26
const uppercaseSetLen = 26
const numericSetLen = 10

// ProcessorCatalog is the function map that points to each Processor to it's entry function. All Processors are listed
// in this map.
var ProcessorCatalog map[string]ProcessorFunc

// AlphaNumericMap is used to keep consistency with scrambled alpha numeric strings.
// For example, if we need to scramble things such as Social Security Numbers, but it is nice to keep track of these
// changes so if we run across the same SSN again we can scramble it to what we already have.
var AlphaNumericMap = map[string]map[string]string{}

// UUIDMap is the Global UUID map for all UUIDs that we anonymize. Similar to AlphaNumericMap this map contains all
// UUIDs and what they are changed to. Some tables use UUIDs as the primary key and this allows us to keep consistency
// in the data set when anonymizing it.
var UUIDMap = map[uuid.UUID]uuid.UUID{}

// IBANMap is the Global IBANs map for all IBANs we anonymize.
var IBANMap = map[string]string{}

var countryCodes = `[{"Code": "AF", "Name": "Afghanistan"},{"Code": "AX", "Name": "\u00c5land Islands"},{"Code": "AL", "Name": "Albania"},{"Code": "DZ", "Name": "Algeria"},{"Code": "AS", "Name": "American Samoa"},{"Code": "AD", "Name": "Andorra"},{"Code": "AO", "Name": "Angola"},{"Code": "AI", "Name": "Anguilla"},{"Code": "AQ", "Name": "Antarctica"},{"Code": "AG", "Name": "Antigua and Barbuda"},{"Code": "AR", "Name": "Argentina"},{"Code": "AM", "Name": "Armenia"},{"Code": "AW", "Name": "Aruba"},{"Code": "AU", "Name": "Australia"},{"Code": "AT", "Name": "Austria"},{"Code": "AZ", "Name": "Azerbaijan"},{"Code": "BS", "Name": "Bahamas"},{"Code": "BH", "Name": "Bahrain"},{"Code": "BD", "Name": "Bangladesh"},{"Code": "BB", "Name": "Barbados"},{"Code": "BY", "Name": "Belarus"},{"Code": "BE", "Name": "Belgium"},{"Code": "BZ", "Name": "Belize"},{"Code": "BJ", "Name": "Benin"},{"Code": "BM", "Name": "Bermuda"},{"Code": "BT", "Name": "Bhutan"},{"Code": "BO", "Name": "Bolivia, Plurinational State of"},{"Code": "BQ", "Name": "Bonaire, Sint Eustatius and Saba"},{"Code": "BA", "Name": "Bosnia and Herzegovina"},{"Code": "BW", "Name": "Botswana"},{"Code": "BV", "Name": "Bouvet Island"},{"Code": "BR", "Name": "Brazil"},{"Code": "IO", "Name": "British Indian Ocean Territory"},{"Code": "BN", "Name": "Brunei Darussalam"},{"Code": "BG", "Name": "Bulgaria"},{"Code": "BF", "Name": "Burkina Faso"},{"Code": "BI", "Name": "Burundi"},{"Code": "KH", "Name": "Cambodia"},{"Code": "CM", "Name": "Cameroon"},{"Code": "CA", "Name": "Canada"},{"Code": "CV", "Name": "Cape Verde"},{"Code": "KY", "Name": "Cayman Islands"},{"Code": "CF", "Name": "Central African Republic"},{"Code": "TD", "Name": "Chad"},{"Code": "CL", "Name": "Chile"},{"Code": "CN", "Name": "China"},{"Code": "CX", "Name": "Christmas Island"},{"Code": "CC", "Name": "Cocos (Keeling) Islands"},{"Code": "CO", "Name": "Colombia"},{"Code": "KM", "Name": "Comoros"},{"Code": "CG", "Name": "Congo"},{"Code": "CD", "Name": "Congo, the Democratic Republic of the"},{"Code": "CK", "Name": "Cook Islands"},{"Code": "CR", "Name": "Costa Rica"},{"Code": "CI", "Name": "C\u00f4te d'Ivoire"},{"Code": "HR", "Name": "Croatia"},{"Code": "CU", "Name": "Cuba"},{"Code": "CW", "Name": "Cura\u00e7ao"},{"Code": "CY", "Name": "Cyprus"},{"Code": "CZ", "Name": "Czech Republic"},{"Code": "DK", "Name": "Denmark"},{"Code": "DJ", "Name": "Djibouti"},{"Code": "DM", "Name": "Dominica"},{"Code": "DO", "Name": "Dominican Republic"},{"Code": "EC", "Name": "Ecuador"},{"Code": "EG", "Name": "Egypt"},{"Code": "SV", "Name": "El Salvador"},{"Code": "GQ", "Name": "Equatorial Guinea"},{"Code": "ER", "Name": "Eritrea"},{"Code": "EE", "Name": "Estonia"},{"Code": "ET", "Name": "Ethiopia"},{"Code": "FK", "Name": "Falkland Islands (Malvinas)"},{"Code": "FO", "Name": "Faroe Islands"},{"Code": "FJ", "Name": "Fiji"},{"Code": "FI", "Name": "Finland"},{"Code": "FR", "Name": "France"},{"Code": "GF", "Name": "French Guiana"},{"Code": "PF", "Name": "French Polynesia"},{"Code": "TF", "Name": "French Southern Territories"},{"Code": "GA", "Name": "Gabon"},{"Code": "GM", "Name": "Gambia"},{"Code": "GE", "Name": "Georgia"},{"Code": "DE", "Name": "Germany"},{"Code": "GH", "Name": "Ghana"},{"Code": "GI", "Name": "Gibraltar"},{"Code": "GR", "Name": "Greece"},{"Code": "GL", "Name": "Greenland"},{"Code": "GD", "Name": "Grenada"},{"Code": "GP", "Name": "Guadeloupe"},{"Code": "GU", "Name": "Guam"},{"Code": "GT", "Name": "Guatemala"},{"Code": "GG", "Name": "Guernsey"},{"Code": "GN", "Name": "Guinea"},{"Code": "GW", "Name": "Guinea-Bissau"},{"Code": "GY", "Name": "Guyana"},{"Code": "HT", "Name": "Haiti"},{"Code": "HM", "Name": "Heard Island and McDonald Islands"},{"Code": "VA", "Name": "Holy See (Vatican City State)"},{"Code": "HN", "Name": "Honduras"},{"Code": "HK", "Name": "Hong Kong"},{"Code": "HU", "Name": "Hungary"},{"Code": "IS", "Name": "Iceland"},{"Code": "IN", "Name": "India"},{"Code": "ID", "Name": "Indonesia"},{"Code": "IR", "Name": "Iran, Islamic Republic of"},{"Code": "IQ", "Name": "Iraq"},{"Code": "IE", "Name": "Ireland"},{"Code": "IM", "Name": "Isle of Man"},{"Code": "IL", "Name": "Israel"},{"Code": "IT", "Name": "Italy"},{"Code": "JM", "Name": "Jamaica"},{"Code": "JP", "Name": "Japan"},{"Code": "JE", "Name": "Jersey"},{"Code": "JO", "Name": "Jordan"},{"Code": "KZ", "Name": "Kazakhstan"},{"Code": "KE", "Name": "Kenya"},{"Code": "KI", "Name": "Kiribati"},{"Code": "KP", "Name": "Korea, Democratic People's Republic of"},{"Code": "KR", "Name": "Korea, Republic of"},{"Code": "KW", "Name": "Kuwait"},{"Code": "KG", "Name": "Kyrgyzstan"},{"Code": "LA", "Name": "Lao People's Democratic Republic"},{"Code": "LV", "Name": "Latvia"},{"Code": "LB", "Name": "Lebanon"},{"Code": "LS", "Name": "Lesotho"},{"Code": "LR", "Name": "Liberia"},{"Code": "LY", "Name": "Libya"},{"Code": "LI", "Name": "Liechtenstein"},{"Code": "LT", "Name": "Lithuania"},{"Code": "LU", "Name": "Luxembourg"},{"Code": "MO", "Name": "Macao"},{"Code": "MK", "Name": "Macedonia, the Former Yugoslav Republic of"},{"Code": "MG", "Name": "Madagascar"},{"Code": "MW", "Name": "Malawi"},{"Code": "MY", "Name": "Malaysia"},{"Code": "MV", "Name": "Maldives"},{"Code": "ML", "Name": "Mali"},{"Code": "MT", "Name": "Malta"},{"Code": "MH", "Name": "Marshall Islands"},{"Code": "MQ", "Name": "Martinique"},{"Code": "MR", "Name": "Mauritania"},{"Code": "MU", "Name": "Mauritius"},{"Code": "YT", "Name": "Mayotte"},{"Code": "MX", "Name": "Mexico"},{"Code": "FM", "Name": "Micronesia, Federated States of"},{"Code": "MD", "Name": "Moldova, Republic of"},{"Code": "MC", "Name": "Monaco"},{"Code": "MN", "Name": "Mongolia"},{"Code": "ME", "Name": "Montenegro"},{"Code": "MS", "Name": "Montserrat"},{"Code": "MA", "Name": "Morocco"},{"Code": "MZ", "Name": "Mozambique"},{"Code": "MM", "Name": "Myanmar"},{"Code": "NA", "Name": "Namibia"},{"Code": "NR", "Name": "Nauru"},{"Code": "NP", "Name": "Nepal"},{"Code": "NL", "Name": "Netherlands"},{"Code": "NC", "Name": "New Caledonia"},{"Code": "NZ", "Name": "New Zealand"},{"Code": "NI", "Name": "Nicaragua"},{"Code": "NE", "Name": "Niger"},{"Code": "NG", "Name": "Nigeria"},{"Code": "NU", "Name": "Niue"},{"Code": "NF", "Name": "Norfolk Island"},{"Code": "MP", "Name": "Northern Mariana Islands"},{"Code": "NO", "Name": "Norway"},{"Code": "OM", "Name": "Oman"},{"Code": "PK", "Name": "Pakistan"},{"Code": "PW", "Name": "Palau"},{"Code": "PS", "Name": "Palestine, State of"},{"Code": "PA", "Name": "Panama"},{"Code": "PG", "Name": "Papua New Guinea"},{"Code": "PY", "Name": "Paraguay"},{"Code": "PE", "Name": "Peru"},{"Code": "PH", "Name": "Philippines"},{"Code": "PN", "Name": "Pitcairn"},{"Code": "PL", "Name": "Poland"},{"Code": "PT", "Name": "Portugal"},{"Code": "PR", "Name": "Puerto Rico"},{"Code": "QA", "Name": "Qatar"},{"Code": "RE", "Name": "R\u00e9union"},{"Code": "RO", "Name": "Romania"},{"Code": "RU", "Name": "Russian Federation"},{"Code": "RW", "Name": "Rwanda"},{"Code": "BL", "Name": "Saint Barth\u00e9lemy"},{"Code": "SH", "Name": "Saint Helena, Ascension and Tristan da Cunha"},{"Code": "KN", "Name": "Saint Kitts and Nevis"},{"Code": "LC", "Name": "Saint Lucia"},{"Code": "MF", "Name": "Saint Martin (French part)"},{"Code": "PM", "Name": "Saint Pierre and Miquelon"},{"Code": "VC", "Name": "Saint Vincent and the Grenadines"},{"Code": "WS", "Name": "Samoa"},{"Code": "SM", "Name": "San Marino"},{"Code": "ST", "Name": "Sao Tome and Principe"},{"Code": "SA", "Name": "Saudi Arabia"},{"Code": "SN", "Name": "Senegal"},{"Code": "RS", "Name": "Serbia"},{"Code": "SC", "Name": "Seychelles"},{"Code": "SL", "Name": "Sierra Leone"},{"Code": "SG", "Name": "Singapore"},{"Code": "SX", "Name": "Sint Maarten (Dutch part)"},{"Code": "SK", "Name": "Slovakia"},{"Code": "SI", "Name": "Slovenia"},{"Code": "SB", "Name": "Solomon Islands"},{"Code": "SO", "Name": "Somalia"},{"Code": "ZA", "Name": "South Africa"},{"Code": "GS", "Name": "South Georgia and the South Sandwich Islands"},{"Code": "SS", "Name": "South Sudan"},{"Code": "ES", "Name": "Spain"},{"Code": "LK", "Name": "Sri Lanka"},{"Code": "SD", "Name": "Sudan"},{"Code": "SR", "Name": "Suriname"},{"Code": "SJ", "Name": "Svalbard and Jan Mayen"},{"Code": "SZ", "Name": "Swaziland"},{"Code": "SE", "Name": "Sweden"},{"Code": "CH", "Name": "Switzerland"},{"Code": "SY", "Name": "Syrian Arab Republic"},{"Code": "TW", "Name": "Taiwan, Province of China"},{"Code": "TJ", "Name": "Tajikistan"},{"Code": "TZ", "Name": "Tanzania, United Republic of"},{"Code": "TH", "Name": "Thailand"},{"Code": "TL", "Name": "Timor-Leste"},{"Code": "TG", "Name": "Togo"},{"Code": "TK", "Name": "Tokelau"},{"Code": "TO", "Name": "Tonga"},{"Code": "TT", "Name": "Trinidad and Tobago"},{"Code": "TN", "Name": "Tunisia"},{"Code": "TR", "Name": "Turkey"},{"Code": "TM", "Name": "Turkmenistan"},{"Code": "TC", "Name": "Turks and Caicos Islands"},{"Code": "TV", "Name": "Tuvalu"},{"Code": "UG", "Name": "Uganda"},{"Code": "UA", "Name": "Ukraine"},{"Code": "AE", "Name": "United Arab Emirates"},{"Code": "GB", "Name": "United Kingdom"},{"Code": "US", "Name": "United States"},{"Code": "UM", "Name": "United States Minor Outlying Islands"},{"Code": "UY", "Name": "Uruguay"},{"Code": "UZ", "Name": "Uzbekistan"},{"Code": "VU", "Name": "Vanuatu"},{"Code": "VE", "Name": "Venezuela, Bolivarian Republic of"},{"Code": "VN", "Name": "Viet Nam"},{"Code": "VG", "Name": "Virgin Islands, British"},{"Code": "VI", "Name": "Virgin Islands, U.S."},{"Code": "WF", "Name": "Wallis and Futuna"},{"Code": "EH", "Name": "Western Sahara"},{"Code": "YE", "Name": "Yemen"},{"Code": "ZM", "Name": "Zambia"},{"Code": "ZW", "Name": "Zimbabwe"}]`

type CountryCode struct {
	Code, Name string
}

var CountryCodes []CountryCode

// init initializes the ProcessorCatalog map for all processors. A processor must be listed here to be accessible.
func init() {
	ProcessorCatalog = map[string]ProcessorFunc{
		"AlphaNumericScrambler": ProcessorAlphaNumericScrambler,
		"EmptyJson":             ProcessorEmptyJson,
		"FakeStreetAddress":     ProcessorAddress,
		"FakeCity":              ProcessorCity,
		"FakeCompanyName":       ProcessorCompanyName,
		"FakeEmailAddress":      ProcessorEmailAddress,
		"FakeFirstName":         ProcessorFirstName,
		"FakeFullName":          ProcessorFullName,
		"FakeIPv4":              ProcessorIPv4,
		"FakeLastName":          ProcessorLastName,
		"FakePhoneNumber":       ProcessorPhoneNumber,
		"FakeState":             ProcessorState,
		"FakeStateAbbrev":       ProcessorStateAbbrev,
		"FakeUsername":          ProcessorUserName,
		"FakeZip":               ProcessorZip,
		"Identity":              ProcessorIdentity, // Default: Does not modify field
		"RandomBoolean":         ProcessorRandomBoolean,
		"RandomDate":            ProcessorRandomDate,
		"RandomDigits":          ProcessorRandomDigits,
		"RandomUUID":            ProcessorRandomUUID,
		"ScrubString":           ProcessorScrubString,
		"IBANScrambler":         ProcessorIBANScrambler,
		"RandomCountryCode":     ProcessorRandomCountryCode,
	}
	if err := json.Unmarshal([]byte(countryCodes), &CountryCodes); err != nil {
		fmt.Println("Failed to parse list of country codes:", err.Error())
		os.Exit(1)
	}

}

// ProcessorFunc is a simple function prototype for the ProcessorMap function pointers.
type ProcessorFunc func(*ColumnMapper, string) (string, error)

func ProcessorIBANScrambler(_ *ColumnMapper, input string) (string, error) {
	if annonymizedIBAN, ok := IBANMap[input]; ok {
		return annonymizedIBAN, nil
	}
	newAnnonymizedIBAN := fmt.Sprintf("%s%s", input[:2], scrambleString(input[2:]))

	IBANMap[input] = newAnnonymizedIBAN

	return newAnnonymizedIBAN, nil
}

func ProcessorRandomCountryCode(_ *ColumnMapper, _ string) (string, error) {
	return CountryCodes[rand.Int63n(int64(len(CountryCodes)))].Code, nil

}

// fakeFuncPtr is a simple function prototype for function pointers to the Fake package's fake functions.
//type fakeFuncPtr func() string

// ProcessorAlphaNumericScrambler will receive the column metadata via ColumnMap and the column's actual data via the
// input string. The processor will scramble all alphanumeric digits and characters, but it will leave all
// non-alphanumerics the same without modification. These values are globally mapped and use the AlphaNumericMap to
// remap values once they are seen more than once.
//
// Example:
// "PUI-7x9vY" = ProcessorAlphaNumericScrambler("ABC-1a2bC")
func ProcessorAlphaNumericScrambler(cmap *ColumnMapper, input string) (string, error) {
	var (
		err       error
		scramble  string
		parentKey string
	)

	// Build the parent key which will be used for mapping columns to each other. Useful for PK/FK relationships
	parentKey = fmt.Sprintf("%s.%s.%s", cmap.ParentSchema, cmap.ParentTable, cmap.ParentColumn)

	// Check to see if we are working on a mapped column
	if cmap.ParentSchema != "" && cmap.ParentTable != "" && cmap.ParentColumn != "" {
		// Check to see if value already exists in AlphaNumericMap
		if len(AlphaNumericMap[parentKey]) < 1 {
			AlphaNumericMap[parentKey] = map[string]string{}
		}
		if len(AlphaNumericMap[parentKey][input]) < 1 {
			scramble = scrambleString(input)
			AlphaNumericMap[parentKey][input] = scramble
		} else {
			// Key already exists so use consistent value
			scramble = AlphaNumericMap[parentKey][input]
		}
	} else {
		scramble = scrambleString(input)
	}

	return scramble, err
}

// ProcessorAddress will return a fake address string that is compiled from the fake library
func ProcessorAddress(cmap *ColumnMapper, input string) (string, error) {
	return fake.StreetAddress(), nil
}

// ProcessorCity will return a real city name that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorCity(cmap *ColumnMapper, input string) (string, error) {
	return fake.City(), nil
}

// ProcessorEmailAddress will return an e-mail address that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorEmailAddress(cmap *ColumnMapper, input string) (string, error) {
	return fake.EmailAddress(), nil
}

// ProcessorFirstName will return a first name that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorFirstName(cmap *ColumnMapper, input string) (string, error) {
	return fake.FirstName(), nil
}

// ProcessorFullName will return a full name that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorFullName(cmap *ColumnMapper, input string) (string, error) {
	return fake.FullName(), nil
}

// ProcessorIdentity will skip anonymization and leave output === input.
func ProcessorIdentity(cmap *ColumnMapper, input string) (string, error) {
	return input, nil
}

func ProcessorIPv4(cmap *ColumnMapper, input string) (string, error) {
	return fake.IPv4(), nil
}

// ProcessorLastName will return a last name that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorLastName(cmap *ColumnMapper, input string) (string, error) {
	return fake.LastName(), nil
}

// ProcessorEmptyJson will return an empty JSON no matter what is the input.
func ProcessorEmptyJson(cmap *ColumnMapper, input string) (string, error) {
	return "{}", nil
}

// ProcessorPhoneNumber will return a phone number that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorPhoneNumber(cmap *ColumnMapper, input string) (string, error) {
	return fake.Phone(), nil
}

// ProcessorState will return a state that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorState(cmap *ColumnMapper, input string) (string, error) {
	return fake.State(), nil
}

// ProcessorStateAbbrev will return a state abbreviation.
func ProcessorStateAbbrev(cmap *ColumnMapper, input string) (string, error) {
	return fake.StateAbbrev(), nil
}

// ProcessorUserName will return a username that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorUserName(cmap *ColumnMapper, input string) (string, error) {
	return fake.UserName(), nil
}

// ProcessorZip will return a zip code that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorZip(cmap *ColumnMapper, input string) (string, error) {
	return fake.Zip(), nil
}

// ProcessorCompanyName will return a company name that is >= 0.4 Jaro-Winkler similar than the input.
func ProcessorCompanyName(cmap *ColumnMapper, input string) (string, error) {
	return fake.Company(), nil
}

// ProcessorRandomBoolean will return a random boolean value.
func ProcessorRandomBoolean(cmap *ColumnMapper, input string) (string, error) {
	var randomBoolean string = "FALSE"
	if rand.Intn(2) == 0 {
		randomBoolean = "TRUE"
	}
	return randomBoolean, nil
}

// ProcessorRandomDate will return a random day and month, but keep year the same (See: HIPAA rules)
func ProcessorRandomDate(cmap *ColumnMapper, input string) (string, error) {
	// ISO 8601/SQL standard ->  2018-08-28
	dateSplit := strings.Split(input, "-")

	if len(dateSplit) < 3 || len(dateSplit) > 3 {
		return "", fmt.Errorf("Date format is not ISO-8601: %q", dateSplit)
	}

	// Parse Year
	year, err := strconv.Atoi(dateSplit[0])
	if err != nil {
		return "", fmt.Errorf("Unable to parse year from date: %q", dateSplit)
	}

	// NOTE: HIPAA only requires we scramble month and day, not year
	scrambledDate := randomizeDate(year)
	return scrambledDate, nil
}

// ProcessorRandomDigits will return a random string of digit(s) keeping the same length of the input.
func ProcessorRandomDigits(cmap *ColumnMapper, input string) (string, error) {
	return fake.DigitsN(len(input)), nil
}

// ProcessorRandomUUID will generate a random UUID and replace the input with the new UUID. The input however will be
// mapped to the output so every occurrence of the input UUID will replace it with the same output UUID that was
// originally created during the first occurrence of the input UUID.
func ProcessorRandomUUID(cmap *ColumnMapper, input string) (string, error) {
	var scrambledUUID string

	inputID, err := uuid.Parse(input)

	if err != nil {
		scrambledUUID = ""
	} else {
		scrambledUUID, err = randomizeUUID(inputID)
	}

	return scrambledUUID, err
}

// ProcessorScrubString will replace the input string with asterisks (*). Useful for blanking out password fields.
func ProcessorScrubString(cmap *ColumnMapper, input string) (string, error) {
	return scrubString(input), nil
}

/*
func jaroWinkler(input string, jwDistance float64, faker fakeFuncPtr) (output string, err error) {
	for counter := 0; counter < jaroWinklerAttempts; counter++ {
		output = faker()
		if jw := matchr.JaroWinkler(input, output, true); jw > jwDistance {
			return output, nil
		}
	}
	return output, fmt.Errorf("Jaro-Winkler: distance < %e for %d attempts. Input: %s, Output: %s",
		jwDistance, jaroWinklerAttempts, input, output)
}
*/

// randomizeUUID creates a random UUID and adds it to the map of input->output. If input already exists it returns
// the output that was previously calculated for input.
func randomizeUUID(input uuid.UUID) (string, error) {
	var (
		finalUUID uuid.UUID
		err       error
	)

	if _, ok := UUIDMap[input]; !ok {
		finalUUID, err = uuid.NewRandom()
		if err != nil {
			return "", err
		}
		UUIDMap[input] = finalUUID
	} else {
		finalUUID = UUIDMap[input]
	}
	return finalUUID.String(), nil
}

// randomizeDate randomizes a day and month for a given year. This function is leap year compatible.
func randomizeDate(year int) string {
	// To find the length of the randomly selected month we need to find the last day of the month.
	// See: https://yourbasic.org/golang/last-day-month-date/

	randMonth := rand.Intn(12) + 1
	monthMaxDay := date(year, randMonth, 0).Day()
	randDay := rand.Intn(monthMaxDay) + 1
	fullDateTime := date(year, randMonth, randDay).Format("2006-01-02")

	return fullDateTime
}

// date returns the date for a given year, month, day. Used to check validity of supplied date.
func date(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

// scrambleString will replace capital letters with a random capital letter, a lower-case letter with a random
// lower-case letter, and numbers with a random number. String size will be the same length and non-alphanumerics will
// be ignored in the input and output.
func scrambleString(input string) string {
	var b strings.Builder

	for i := 0; i < len(input); i++ {
		switch c := input[i]; {
		case c >= 'a' && c <= 'z':
			b.WriteString(randomLowercase())
		case c >= 'A' && c <= 'Z':
			b.WriteString(randomUppercase())
		case c >= '0' && c <= '9':
			b.WriteString(randomNumeric())
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// scrubString replaces the input string with asterisks (*) and returns it as the output.
func scrubString(input string) string {
	return strings.Repeat("*", utf8.RuneCountInString(input))
}

// randomLowercase will pick a random location in the lowercase constant string and return the letter at that position.
func randomLowercase() string {
	return string(lowercaseSet[rand.Intn(lowercaseSetLen)])
}

// randomUppercase will pick a random location in the uppercase constant string and return the letter at that position.
func randomUppercase() string {
	return string(uppercaseSet[rand.Intn(uppercaseSetLen)])
}

// randomNumeric will return a random location in the numeric constant string and return the number at that position.
func randomNumeric() string {
	return string(numericSet[rand.Intn(numericSetLen)])
}

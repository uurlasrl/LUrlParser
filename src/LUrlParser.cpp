/*
 * Lightweight URL & URI parser (RFC 1738, RFC 3986)
 * https://github.com/corporateshark/LUrlParser
 *
 * The MIT License (MIT)
 *
 * Copyright (C) 2015-2020 Sergey Kosarevsky (sk@linderdaum.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "LUrlParser/LUrlParser.h"

#include <algorithm>
#include <cstring>
#include <sstream>
//#include <stdlib.h>
#include <string>
#include <stdexcept>
#include <cctype>

namespace{
	// check if the scheme name is valid
	bool isSchemeValid(const std::string& schemeName){
		for (auto c : schemeName){
			if (!isalpha(c) && c != '+' && c != '-' && c != '.') return false;
		}

		return true;
	}

	std::string urlDecode(const std::string& value) {
		std::string decoded;
		for (size_t i = 0; i < value.length(); ++i) {
			if (value[i] == '%') {
				if (i + 2 >= value.length()) {
					throw std::invalid_argument("Invalid URL encoding");
				}
				// Convert the two hex digits to a character
				int hexValue = std::stoi(value.substr(i + 1, 2), nullptr, 16);
				decoded += static_cast<char>(hexValue);
				i += 2; // Skip the next two characters, as they've been processed
			} else if (value[i] == '+') {
				// Replace '+' with a space
				decoded += ' ';
			} else {
				// Normal character
				decoded += value[i];
			}
		}
		return decoded;
	}

}

bool LUrlParser::ParseURL::getPort(int* outPort) const{
	if (!isValid()) { return false; }

	const int port = atoi(port_.c_str());

	if (port <= 0 || port > 65535) { return false; }

	if (outPort) { *outPort = port; }

	return true;
}

// based on RFC 1738 and RFC 3986
LUrlParser::ParseURL *LUrlParser::ParseURL::parseURL(const std::string& URL){
	auto *result = new LUrlParser::ParseURL();

	const char* currentString = URL.c_str();

	/*
	 *	<scheme>:<scheme-specific-part>
	 *	<scheme> := [a-z\+\-\.]+
	 *	For resiliency, programs interpreting URLs should treat upper case letters as equivalent to lower case in scheme names
	 */

	 // try to read scheme
	{

		const char* localString = (!strchr(currentString, ':'))?(strchr(currentString, '/')-1):strchr(currentString, ':');

		if (!localString){
			delete result;
			return new ParseURL(LUrlParserError_NoUrlCharacter);
		}

		// save the scheme name
		result->scheme_ = std::string(currentString, localString - currentString);

		if (!isSchemeValid(result->scheme_)){
			return new ParseURL(LUrlParserError_InvalidSchemeName);
		}

		// scheme should be lowercase
		std::transform(result->scheme_.begin(), result->scheme_.end(), result->scheme_.begin(), ::tolower);

		// skip ':'
		currentString = localString + 1;
	}

	/*
	 *	//<user>:<password>@<host>:<port>/<url-path>
	 *	any ":", "@" and "/" must be normalized
	 */

	 // skip "//"
	if (*currentString++ != '/') { delete result; return new ParseURL(LUrlParserError_NoDoubleSlash);}
	if (*currentString++ != '/') { delete result; return new ParseURL(LUrlParserError_NoDoubleSlash);}

	// check if the user name and password are specified
	bool bHasUserName = false;

	const char* localString = currentString;

	while (*localString){
		if (*localString == '@'){
			// user name and password are specified
			bHasUserName = true;
			break;
		}else if (*localString == '/'){
			// end of <host>:<port> specification
			bHasUserName = false;
			break;
		}

		localString++;
	}

	// user name and password
	localString = currentString;

	if (bHasUserName){
		// read user name
		while (*localString && *localString != ':' && *localString != '@') localString++;

		result->userName_ = std::string(currentString, localString - currentString);

		// proceed with the current pointer
		currentString = localString;

		if (*currentString == ':'){
			// skip ':'
			currentString++;

			// read password
			localString = currentString;

			while (*localString && *localString != '@') localString++;

			result->password_ = std::string(currentString, localString - currentString);

			currentString = localString;
		}

		// skip '@'
		if (*currentString != '@'){
			delete result;
			return new ParseURL(LUrlParserError_NoAtSign);
		}

		currentString++;
	}

	const bool bHasBracket = (*currentString == '[');

	// go ahead, read the host name
	localString = currentString;

	while (*localString){
		if (bHasBracket && *localString == ']'){
			// end of IPv6 address
			localString++;
			break;
		}else if (!bHasBracket && (*localString == ':' || *localString == '/')){
			// port number is specified
			break;
		}

		localString++;
	}

	result->host_ = std::string(currentString, localString - currentString);

	currentString = localString;

	// is port number specified?
	if (*currentString == ':'){
		currentString++;

		// read port number
		localString = currentString;

		while (*localString && *localString != '/') localString++;

		result->port_ = std::string(currentString, localString - currentString);

		currentString = localString;
	}

	// end of string
	if (!*currentString){
		result->errorCode_ = LUrlParserError_Ok;
		return result;
	}

	// skip '/'
	if (*currentString != '/'){
		delete result;
		return new ParseURL(LUrlParserError_NoSlash);
	}

	currentString++;

	// parse the path
	localString = currentString;

	while (*localString && *localString != '#' && *localString != '?') localString++;

	result->path_ = std::string(currentString, localString - currentString);

	currentString = localString;

	// check for query
	if (*currentString == '?'){
		// skip '?'
		currentString++;

		// read query
		localString = currentString;

		while (*localString&&* localString != '#') localString++;

		result->query_ = std::string(currentString, localString - currentString);

		std::string key_value;
		std::string key;
		std::string value;
		std::stringstream ss(result->query_);
		while (std::getline(ss, key_value, '&')){
			std::stringstream ss2(key_value);
			std::getline(ss2, key, '=');
			std::getline(ss2, value, '&');

			result->url_parameters_[key] = urlDecode(value);
		}

		currentString = localString;
	}

	// check for fragment
	if (*currentString == '#'){
		// skip '#'
		currentString++;

		// read fragment
		localString = currentString;

		while (*localString) localString++;

		result->fragment_ = std::string(currentString, localString - currentString);

		currentString = localString;
	}

	result->errorCode_ = LUrlParserError_Ok;

	return result;
}

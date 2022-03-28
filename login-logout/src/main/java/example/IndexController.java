/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.schema.XSString;

import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

	@GetMapping("/")
	public String index(Model model, ExpiringUsernameAuthenticationToken authentication) {
		SAMLCredential credential = (SAMLCredential) authentication.getCredentials();
		String emailAddress = credential.getAttributeAsString("email");
		model.addAttribute("emailAddress", emailAddress);
		List<UserAttribute> userAttributes = new ArrayList<>();
		for (Attribute attribute : credential.getAttributes()) {
			List<String> attributeValues = getAttributesAsString(attribute);
			userAttributes.add(new UserAttribute(attribute.getName(), attributeValues));
		}
		model.addAttribute("userAttributes", userAttributes);
		return "index";
	}

	private List<String> getAttributesAsString(Attribute attribute) {
		return attribute.getAttributeValues().stream()
				.filter(XSString.class::isInstance).map(XSString.class::cast)
				.map(XSString::getValue)
				.collect(Collectors.toList());
	}

	public static class UserAttribute {

		private final String name;

		private final List<String> values;

		public UserAttribute(String name, List<String> values) {
			this.name = name;
			this.values = values;
		}

		public String getName() {
			return this.name;
		}

		public List<String> getValues() {
			return this.values;
		}
	}

}

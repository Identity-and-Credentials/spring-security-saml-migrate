package example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoggedOutController {

	@GetMapping("/logged-out")
	public String loggedOut() {
		return "logged-out";
	}

}

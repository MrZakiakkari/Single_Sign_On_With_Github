package Single_Sign_On_With_Github.sso;

import java.util.Collections;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SsoApplication extends WebSecurityConfigurerAdapter
{

	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal)
	{
		return Collections.singletonMap("name", principal.getAttribute("login"));
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception
	{
		httpSecurity
				.authorizeRequests(authorizeRequestsCustomizer -> authorizeRequestsCustomizer
				.antMatchers("/", "/error", "/webjars/**").permitAll()
				.anyRequest().authenticated()
				)
				.exceptionHandling(exceptionHandlingCustomizer -> exceptionHandlingCustomizer
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				)
				.csrf(csrfCustomizer -> csrfCustomizer
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				)
				.logout(logoutCustomizer -> logoutCustomizer
				.logoutSuccessUrl("/").permitAll()
				)
				.oauth2Login();
	}

	public static void main(String[] args)
	{
		SpringApplication.run(SsoApplication.class, args);
	}

}

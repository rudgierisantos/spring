package curso.springboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private ImplementacaoUserDetailsService ImplementacaoUserDetailsService;

	@Override // Configura as solicitações de acesso por http
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable() // Desativa as configurações padrão de memória.
				.authorizeRequests() // Permite restringir acessos.
				.antMatchers(HttpMethod.GET, "/").permitAll() // Qualquer usuário acessa a página inicial
				.antMatchers(HttpMethod.GET, "/cadastropessoa").hasAnyRole("ADMIN")
				.anyRequest().authenticated().and().formLogin().permitAll() // permite qualquer usuario
				.loginPage("/login")
				.defaultSuccessUrl("/cadastropessoa")
				.failureUrl("/login?error=true")
				.and().logout().logoutSuccessUrl("/login") // Mapeia URL de logout e invalida usuário autenticado
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));

	}
	
	@Override //Cria autenticação do usuario com o banco de dados ou em memoria
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
				auth.userDetailsService(ImplementacaoUserDetailsService)
				.passwordEncoder(new BCryptPasswordEncoder());
		
		
		
		
		
				/*auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
				.withUser("rudgieri")
				.password("$2a$10$9aWjY4ocgSHrQPOL0ZiKbe0knvjyDiAHExAQwAah3VRfS0pqrQesC")
				.roles("ADMIN"); */
	}

	@Override //Ignora URL especificas
	public void configure(WebSecurity web) throws Exception {
				web.ignoring().antMatchers("/materialize/**");
	}
}

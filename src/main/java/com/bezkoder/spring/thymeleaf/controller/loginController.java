package com.bezkoder.spring.thymeleaf.controller;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class loginController {
	
	 private static final Logger logger = LoggerFactory.getLogger(loginController.class);
	 
	 @GetMapping("/login")
	    public String login(@RequestParam(value = "error", required = false) String error, @RequestParam(value = "expired", required = false) String expired,Model model, Principal principal, RedirectAttributes flash) {
		 logger.info("iniciando sesión " );
		 if (error != null) {
		        model.addAttribute("error", "error al iniciar sesion ");
		        logger.info("Credenciales inválidas. " + error);
		    }
		 
		 if(principal !=null){
			 flash.addFlashAttribute("info", "Ya se ha iniciado sesión");
			 logger.info("info " + "Ya se ha iniciado sesión");
			 return "redirect:/tutorials";
		 }
	        return "login"; 
	    }
	 
		@GetMapping("/")
	    public String home() {
	        return "redirect:/tutorials";
	    }
		
	  // Login form with error
	  @RequestMapping("/login-error.html")
	  public String loginError(Model model) {
	    model.addAttribute("loginError", true);
	    return "login.html";
	  }
	  
	  @RequestMapping(value="/logout", method = RequestMethod.GET)
	  public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
		  logger.info("Salida cierre: ");
	      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	      if (auth != null){    
	          new SecurityContextLogoutHandler().logout(request, response, auth);
	          logger.info("auth at:: " + auth.toString());
	      }
	      return "redirect:/login?logout";
	  }
	  
}

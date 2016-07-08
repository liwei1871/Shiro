package com.atguigu.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ShiroHandler {
	
	@Autowired
	private MyShiroService myShiroService;
	
	@RequestMapping("/test")
	public String test(){
		myShiroService.test();
		return "test";
	}

	@RequestMapping(value="/login-shiro")
	public String login(@RequestParam("userName") String userName,
			@RequestParam("password") String password){
		
		//获取当前Subject 对象
		Subject currentUser  = SecurityUtils.getSubject();
		
		//检验当前用户是否被认证，即是否登录
		if(!currentUser.isAuthenticated()){
			// 把用户名和密码封装为一个 UsernamePasswordToken 对象. 
			UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
			token.setRememberMe(true);
			
			try {
				// 执行登录. 调用 Subject 的 login(UsernamePasswordToken) 方法.
				currentUser.login(token);
				
			} catch (AuthenticationException ae) {
				
				System.out.println("登录失败：" + ae.getMessage());
				
				return "redirect:/login.jsp";
				
			}
			
		}
		
		return "success";
	}
	
}

package com.atguigu.shiro;

import org.apache.shiro.authz.annotation.RequiresRoles;

public class MyShiroService {

	@RequiresRoles("tester")
	public void test() {
		System.out.println("访问了testService...");
	}
	
	
	
	
}

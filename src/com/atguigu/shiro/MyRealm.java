package com.atguigu.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm {

	
	/**
	 * 当访问受保护的资源时，调用该方法doGetAuthorizationInfo
	 * 可以从 PrincipalCollection 类型的参数中来获取当前登陆用户的信息
	 */
	//在此方法中进行授权
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		
		//System.out.println(principals);
		//获取登录信息getPrimaryPrincipal()
		Object principal = principals.getPrimaryPrincipal();
		
		System.out.println("登录用户：" + principal);
		
		//把权限信息封装为一个SimpleAuthorizationInfo 对象 并返回
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRole("user");
		
		if("admin".equals(principal)){
			info.addRole("admin");
		}
		if("user".equals(principal)){
			info.addRole("tester");
		}
		
		return info;
	}

	/**
	 * 认证的流程：在handler中调用Subject
	 * 的login(UsernamePasswordToken)方法时shiro会回调AuthenticatingRealm实现类的
	 * doGetAuthenticationInfo方法且方法参数AuthenticationToken 的 对象即为调用login方法时传入的对象
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {

		// 1.先把AuthenticationToken对象强转为UsernamePasswordtoken 对象
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;

		// 2.从UsernamePasswordToken 对象中获取userName 但不需要获取password
		String userName = upToken.getUsername();

		// 3.利用userName调用Dao方法，从数据库中获取对应的用户信息
		System.out.println("利用 username:" + userName + "从数据库中获取用户信息");

		if ("AAA".equals(userName)) {

			throw new UnknownAccountException("AAA不能认证");
		}

		// 把获取的用户信息封装为SimpleAuthenticationInfo 对象返回
		// 实际登录用户信息. 可以为 username. 也可以是一个实体类的对象
		String principal = userName;

		// 凭证信息：即密码
		String hashedCredentials = null;

		if ("user".equals(userName)) {
			hashedCredentials = "098d2c478e9c11555ce2823231e02ec1";
		} else if ("admin".equals(userName)) {
			hashedCredentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}

		// 盐值
		// 若需要使用密码进行盐值加密, 则需要在参加 SimpleAuthenticationInfo 对象时
		// 使用 SimpleAuthenticationInfo(principal, hashedCredentials,
		// credentialsSalt, realmName)
		ByteSource credentialsSalt = ByteSource.Util.bytes(userName);

		//realm 的 name, 只需要调用 AuthorizingRealm 中已经定义好的 getName() 方法即可.
		String realmName = getName();

		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal,
				hashedCredentials, credentialsSalt, realmName);

		return info;
	}
	
	
	/**
	 * 计算对应的加密后的密码
	 */
	public static void main(String[] args) {
		
		//加密方式的名称
		String algorithmName = "MD5";
		
		String credentials = "123456";//密码，需要加密的对象
		
		ByteSource salt = ByteSource.Util.bytes("admin"); //盐值
		
		int hashIterations = 1024; //加密次数
		
		Object result = new SimpleHash(algorithmName, credentials, salt, hashIterations);
		
		System.out.println(result);
				
		
	}
	
}

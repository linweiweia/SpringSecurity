package com.ww.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author linweiwei
 * @version 1.0
 * @date 2020-09-23 16:10
 * @describe:
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //认证
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasAnyRole("vip1")
                .antMatchers("/level2/**").hasAnyRole("vip2")
                .antMatchers("/level3/**").hasAnyRole("vip3");

        //自动登入(没有权限的就会自动登入)
        //loginPage就是登入页的地址，所以和控制器一样（这个可以不用配）
        //loginProcessingUrl就是表单提交的处理地址所以要和login.html中action一样
        http.formLogin()
                .loginPage("/toLogin")
                .usernameParameter("account")
                .passwordParameter("pwd")
                .loginProcessingUrl("/login");

        //自动注销（消除cookie，session）
        http.logout();

        //退出成功后跳到首页
        //关闭csrf功能:跨站请求伪造,默认只能通过post方式提交logout请求
        http.csrf().disable();
        http.logout().logoutSuccessUrl("/");

        //记住我
        http.rememberMe().rememberMeParameter("rememberaaaa");
    }

    //授权
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //从数据库中获取账号密码
        //auth.jdbcAuthentication

        //从内存中获取账号密码
        //从前端获取的账号密码需要加密保证安全
        // spring security 官方推荐的是使用bcrypt加密方式。
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder()).withUser("admin")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1", "vip2", "vip3")
                .and().withUser("guest").password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1");
    }
}

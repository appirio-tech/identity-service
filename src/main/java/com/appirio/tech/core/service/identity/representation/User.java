package com.appirio.tech.core.service.identity.representation;

import static com.appirio.tech.core.service.identity.util.Constants.*;

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;
import com.appirio.tech.core.api.v3.model.annotation.ApiMapping;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.ldap.MemberStatus;
import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * User entity
 * 
 * <p>
 * Changes in the version 1.1 72h TC Identity Service API Enhancements v1.0
 * - add sso login field
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public class User extends AbstractIdResource {

	private String handle;
	private String email;
	private String firstName;
	private String lastName;
	private Credential credential;
	private List<UserProfile> profiles;
	private String status;
	private Integer emailStatus;
	private Country country;
	private String regSource;
	private String utmSource;
	private String utmMedium;
	private String utmCampaign;
	private List<Role> roles;
	private Boolean mfaEnabled;
	private Boolean diceEnabled;

	private String primaryRole;
	
    /**
     * Represents the ssoLogin attribute.
     */
	private boolean ssoLogin;
	
	public String getHandle() {
		return handle;
	}
	
	public void setHandle(String handle) {
		this.handle = handle;
	}

	public String getPrimaryRole() {
		return primaryRole;
	}

	public void setPrimaryRole(String primaryRole) {
		this.primaryRole = primaryRole;
	}
	
	public String getEmail() {
		return email;
	}
	
	public void setEmail(String email) {
		this.email = email;
	}
	
	public String getFirstName() {
		return firstName;
	}
	
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	
	public String getLastName() {
		return lastName;
	}
	
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	
	public Boolean isActive() {
		return INTERNAL_STATUS_ACTIVE.equals(this.status);
	}
	
	public void setActive(Boolean active) {
		this.status = (active!=null && active) ? INTERNAL_STATUS_ACTIVE : INTERNAL_STATUS_UNVERIFIED;
	}
	
	// Internal representation of user's status (Active or not)
	protected static final String INTERNAL_STATUS_ACTIVE = MemberStatus.ACTIVE.getValue();
	protected static final String INTERNAL_STATUS_UNVERIFIED = MemberStatus.UNVERIFIED.getValue();
	public String getStatus() {
		return this.status;
	}
	
	public void setStatus(String status) {
		this.status = status;
	}
	
	// Reverted to resolve a side-effected issue.
	//@ApiMapping(queryDefault=false)
	public Credential getCredential() {
		return credential;
	}
	
	public void setCredential(Credential credential) {
		this.credential = credential;
	}
	
	/**
	 * returns profiles[0]
	 */
	public UserProfile getProfile() {
		return (profiles!=null && profiles.size()>0) ? profiles.get(0) : null;
	}

	@SuppressWarnings("serial")
	@Deprecated /* this will be replaced with setProfiles(profiles) */
	public void setProfile(UserProfile profile) {
		this.profiles = new LinkedList<UserProfile>(){{ add(profile); }};
	}
	
	@ApiMapping(queryDefault=false)
	public List<UserProfile> getProfiles() {
		return profiles;
	}

	public void setProfiles(List<UserProfile> profiles) {
		this.profiles = profiles;
	}

	// Internal representation of email's status (Active or not)
	public static final int INTERNAL_EMAIL_STATUS_ACTIVE = 1;
	public boolean isEmailActive() {
		return getEmailStatus() == null ? false : (INTERNAL_EMAIL_STATUS_ACTIVE == getEmailStatus());
	}
	
	@JsonIgnore
	public Integer getEmailStatus() {
		return emailStatus;
	}

	public void setEmailStatus(Integer emailStatus) {
		this.emailStatus = emailStatus;
	}

	public Country getCountry() {
		return country;
	}

	public void setCountry(Country country) {
		this.country = country;
	}
	
	public String getRegSource() {
		return regSource;
	}

	public void setRegSource(String regSource) {
		this.regSource = regSource;
	}

	public String getUtmSource() {
		return utmSource;
	}

	public void setUtmSource(String utmSource) {
		this.utmSource = utmSource;
	}

	public String getUtmMedium() {
		return utmMedium;
	}

	public void setUtmMedium(String utmMedium) {
		this.utmMedium = utmMedium;
	}

	public String getUtmCampaign() {
		return utmCampaign;
	}

	public void setUtmCampaign(String utmCampaign) {
		this.utmCampaign = utmCampaign;
	}

	public List<Role> getRoles() { return roles; }

	public void setRoles(List<Role> roles) { this.roles = roles; }

	public Boolean getMfaEnabled() {
		return mfaEnabled;
	}

	public void setMfaEnabled(Boolean mfaEnabled) {
		this.mfaEnabled = mfaEnabled;
	}

	public Boolean getDiceEnabled() {
		return diceEnabled;
	}

	public void setDiceEnabled(Boolean diceEnabled) {
		this.diceEnabled = diceEnabled;
	}
	
	@JsonIgnore
	public boolean isReferralProgramCampaign() {
		return "ReferralProgram".equals(this.utmCampaign);
	}

	public String validate() {
		String result = validateFirstName();
		if(result!=null) return result;
		
		result = validateLastName();
		if(result!=null) return result;
		
		result = validatePassoword();
		if(result!=null) return result;

		result = validateHandle();
		if(result!=null) return result;
		
		result = validateEmail();
		if(result!=null) return result;
		
		return result;
	}


	//
	/**
	 * do validation check on handle
	 * @return error message or null for valid status
	 */
	public String validateHandle() {
		return createHandleValidator().validateHandle(this.handle);
	}
	protected HandleValidator createHandleValidator() {
		return DiscourseHandleValidator.isEnabled() ?
				new DiscourseHandleValidator() : new HandleValidator();		
	}
	
	public String validateEmail() {
		// Mandatory
		if (this.email==null || this.email.length()==0)
			return String.format(MSG_TEMPLATE_MANDATORY, "Email address");

		// Range check
		if (this.email.length() > MAX_LENGTH_EMAIL) {
			return String.format(MSG_TEMPLATE_INVALID_EMAIL_LENGTH, "email address", MAX_LENGTH_EMAIL);
		}
		
		Matcher matcher = EMAIL_PATTERN.matcher(email);
		if (!matcher.matches()) {
			return MSG_TEMPLATE_INVALID_EMAIL;
		}
		return null;
	}

	public String validateFirstName() {
		// Not mandatory
		if (this.firstName==null || this.firstName.length()==0)
			return null;
		// Range check
		if (this.firstName.length() > MAX_LENGTH_FIRST_NAME) {
			return String.format(MSG_TEMPLATE_INVALID_MAX_LENGTH, "first name", MAX_LENGTH_FIRST_NAME);
		}
		return null;
	}
	
	public String validateLastName() {
		// Not mandatory
		if (this.lastName==null || this.lastName.length()==0)
			return null;
		// Range check
		if (this.lastName.length() > MAX_LENGTH_LAST_NAME) {
			return String.format(MSG_TEMPLATE_INVALID_MAX_LENGTH, "last name", MAX_LENGTH_LAST_NAME);
		}
		return null;
	}
	
	protected String validateName(String fieldName, String nameValue, int maxlength) {
		// Not mandatory
		if (nameValue==null || nameValue.length()==0)
			return null;
		// Range check
		if (nameValue.length() > maxlength) {
			return String.format(MSG_TEMPLATE_INVALID_MAX_LENGTH, fieldName, maxlength);
		}
		return null;
	}
	
	public String validatePassoword() {
		String password = getCredential()!=null ? getCredential().getPassword() : null;
		return this.passwordValidator.validatePassword(password);
	}
	
	@JsonIgnore
	protected PasswordValidator passwordValidator = new PasswordValidator();
	
	
	protected static class HandleValidator {
		
		public String validateHandle(String handle) {
			// Mandatory
			if (handle==null || handle.length()==0)
				return String.format(MSG_TEMPLATE_MANDATORY, "Handle");
			
			// Range check
			if (handle.length() < MIN_LENGTH_HANDLE || handle.length() > MAX_LENGTH_HANDLE) {
				return MSG_TEMPLATE_INVALID_HANDLE_LENGTH;
			}
			if (handle.contains(" ")) {
				return MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_SPACE;
			}
			if (!Utils.containsOnly(handle, HANDLE_ALPHABET, false)) {
				return MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_FORBIDDEN_CHAR;
			}
			if (Utils.containsOnly(handle, HANDLE_PUNCTUATION, false)) {
				return MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_ONLY_PUNCTUATION;
			}
			if (handle.toLowerCase().trim().startsWith("admin")) {
				return MSG_TEMPLATE_INVALID_HANDLE_STARTS_WITH_ADMIN;
			}
			/*
			if (Utils.checkInvalidHandle(handle)) {
				return "The handle you entered is not valid.";
			}
			*/
			return null;
		}
	}
	
	protected static class DiscourseHandleValidator extends HandleValidator {
		
		public static final String ENV_DISCOURSE_VALIDATION = "DISCOURSE_VALIDATION";
		public static final int MIN_LENGTH_DISCOURSE_HANDLE = 3;
		public static final int MAX_LENGTH_DISCOURSE_HANDLE = 15;
		public static final Pattern CHARS_PATTERN = Pattern.compile("[^\\w.-]");
		public static final Pattern FIRST_CHAR_PATTERN = Pattern.compile("\\W");
		public static final Pattern LAST_CHAR_PATTERN = Pattern.compile("[^A-Za-z0-9]");
		public static final Pattern DOUBLE_SPECIAL_PATTERN = Pattern.compile("[-_.]{2,}");
		public static final Pattern CONFUSING_EXTENSIONS_PATTERN = Pattern.compile("\\.(js|json|css|htm|html|xml|jpg|jpeg|png|gif|bmp|ico|tif|tiff|woff)$");
		public static final String[] RESERVED_USERNAMES = {
			"admin",
			"moderator",
			"administrator",
			"mod",
			"sys",
			"system",
			"community",
			"info",
			"you",
			"name",
			"username",
			"user",
			"nickname",
			"discourse",
			"discourseorg",
			"discourseforum",
			"support",
		};
		
		/**
		 * [username_validator]
		 * https://github.com/discourse/discourse/blob/master/app/models/username_validator.rb
		 */
		public String validateHandle(String handle) {
			// TC validation
			String err = super.validateHandle(handle);
			if(err != null)
				return err;
			String prefix = REASON_INVALID_HANDLE+"__";
			// Range check
			if (handle.length() < MIN_LENGTH_DISCOURSE_HANDLE || handle.length() > MAX_LENGTH_DISCOURSE_HANDLE) {
				return prefix+String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "Handle", MIN_LENGTH_DISCOURSE_HANDLE, MAX_LENGTH_DISCOURSE_HANDLE);
			}
			// username_char_valid
			Matcher matcher = CHARS_PATTERN.matcher(handle);
			if (matcher.find()) {
				return prefix+"Handle must only include numbers, letters and underscores";
			}
			// username_first_char_valid
			matcher = FIRST_CHAR_PATTERN.matcher(handle.substring(0, 1));
			if (matcher.matches()) {
				return prefix+"Handle must begin with a letter, a number or an underscore";
			}
			// username_last_char_valid
			matcher = LAST_CHAR_PATTERN.matcher(handle.substring(handle.length()-1));
			if (matcher.matches()) {
				return prefix+"Handle must end with a letter or a number";
			}
			// username_no_double_special
			matcher = DOUBLE_SPECIAL_PATTERN.matcher(handle);
			if (matcher.find()) {
				return prefix+"Handle must not contain a sequence of 2 or more special chars (.-_)";
			}
			// username_does_not_end_with_confusing_suffix
			matcher = CONFUSING_EXTENSIONS_PATTERN.matcher(handle.toLowerCase());
			if (matcher.find()) {
				return prefix+"Handle must not end with a confusing suffix like .json or .png etc.";
			}
			// reserved usernames
			for (String n : RESERVED_USERNAMES) {
				if(n.equalsIgnoreCase(handle))
					return prefix+"The entered handle is not allowed. Please choose another one";
			}
			
			return null;
		}
		
		public static boolean isEnabled() {
			String env = System.getenv(ENV_DISCOURSE_VALIDATION);
			if(env==null)
				env = System.getProperty(ENV_DISCOURSE_VALIDATION);
			if(env==null)
				return false;
			
			env = env.trim();
			return env.equalsIgnoreCase("true") || env.equalsIgnoreCase("on") || env.equalsIgnoreCase("1");
		}
	}	
	
	protected static class PasswordValidator {
		
		public String validatePassword(String password) {
			// Mandatory
			if (password==null || password.length()==0)
				return String.format(MSG_TEMPLATE_MANDATORY, "Password");
			
			// Range check
			if (password.length() < MIN_LENGTH_PASSWORD || password.length() > MAX_LENGTH_PASSWORD) {
				return String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "password", MIN_LENGTH_PASSWORD, MAX_LENGTH_PASSWORD);
			}

			// Check if it has a letter.
			if (!ALPHABET_PATTERN.matcher(password).find()) {
				return MSG_TEMPLATE_INVALID_PASSWORD_LETTER;
			}
			
			// Check if it has punctuation symbol
			if (!SYMBOL_PATTERN.matcher(password).find() && !NUMBER_PATTERN.matcher(password).find()) {
				return MSG_TEMPLATE_INVALID_PASSWORD_NUMBER_SYMBOL;
			}
			
			return null;
		}
	}
	
	// V2 implementation
	protected static class PasswordValidatorV2 extends PasswordValidator {
		@Override
		public String validatePassword(String password) {
			// Mandatory
			if (password==null || password.length()==0)
				return String.format(MSG_TEMPLATE_MANDATORY, "Password");
			
			// Range check
			if (password.length() < MIN_LENGTH_PASSWORD_V2 || password.length() > MAX_LENGTH_PASSWORD_V2) {
				return String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "password", MIN_LENGTH_PASSWORD_V2, MAX_LENGTH_PASSWORD_V2);
			}
			// length OK, check password strength.
			int strength = calculatePasswordStrength(password);
			switch (strength) {
			case 0:
			case 1:
			case 2:
				return MSG_TEMPLATE_INVALID_PASSWORD;
			default:
				break;
			}
			return null;
		}
		public int calculatePasswordStrength(String password) {
			int result = 0;
			password = password.trim();

			// Check if it has lower case characters.
			Matcher matcher = LOWER_CASE_PATTERN.matcher(password);
			if (matcher.find()) {
				result++;
			}

			// Check if it has upper case character.
			matcher = UPPER_CASE_PATTERN.matcher(password);
			if (matcher.find()) {
				result++;
			}

			// Check if it has punctuation symbol
			matcher = SYMBOL_PATTERN.matcher(password);
			if (matcher.find()) {
				result++;
			}

			// Check if it has number.
			matcher = NUMBER_PATTERN.matcher(password);
			if (matcher.find()) {
				result++;
			}
			return result;
		}
	}

    /**
     * Get ssoLogin.
     * @return the ssoLogin. 
     */
    public boolean isSsoLogin() {
        return this.ssoLogin;
    }
    
    /**
     * Set ssoLogin.
     * @return the ssoLogin to set. 
     */
    public void setSsoLogin(boolean ssoLogin) {
        this.ssoLogin = ssoLogin;
    }
}

package com.appirio.tech.core.service.identity.util;

import com.appirio.tech.core.service.identity.representation.User;

public class UserQueryHelper {

	public ConditionBuilder createConditionBuilder(String paramKey, final User user, StringBuilder buffer) {
		if("id".equals(paramKey))
			return new IDConditionBuilder(buffer, user);
		if("handle".equals(paramKey))
			return new HandleConditionBuilder(buffer, user);
		if("email".equals(paramKey))
			return new EmailConditionBuilder(buffer, user);
		if("active".equals(paramKey))
			return new StatusConditionBuilder(buffer, user);
		return null;
	}
	
	public static class ConditionBuilder {
		protected String column;
		protected Object value;
		protected StringBuilder whereClause;
		public ConditionBuilder(StringBuilder buffer, String column, Object value) {
			this.whereClause = buffer!=null ? buffer : new StringBuilder();
			this.column = column;
			this.value = value;
		}
		public StringBuilder build(boolean isLike) {
			addCondition(column, value);
			return whereClause;
		}

		protected String op(boolean isLike) {
			return isLike ? " like " : " = ";
		}
		protected String arg(boolean isLike, String value) {
			if(value==null)
				return null;
			return isLike ? value.replaceAll("\\*", "%") : value;
		}
		protected void addCondition(String column, String placeHolder, boolean isLike) {
			if(whereClause.length()>0)
				whereClause.append(" AND ");
			whereClause.append(column).append(op(isLike)).append(placeHolder);
		}
		protected void addCondition(String column, Object value) {
			if(whereClause.length()>0)
				whereClause.append(" AND ");
			whereClause.append(column).append(" = ").append(value);
		}
	}
	public static class PlaceHolderConditionBuilder extends ConditionBuilder {
		protected String placeHolder;
		public PlaceHolderConditionBuilder(StringBuilder buffer, String column, String placeHolder) {
			super(buffer, column, null);
			this.placeHolder = placeHolder;
		}
		@Override
		public StringBuilder build(boolean isLike) {
			addCondition(column, placeHolder, isLike);
			return whereClause;
		}
	}
	
	public static class IDConditionBuilder extends ConditionBuilder {
		public IDConditionBuilder(StringBuilder buffer, User user) {
			super(buffer, "u.user_id", user.getId().getId());
		}
	}
	public static class HandleConditionBuilder extends PlaceHolderConditionBuilder {
		protected User user;
		public HandleConditionBuilder(StringBuilder buffer, User user) {
			super(buffer, "u.handle_lower", "LOWER(:u.handle)");
			this.user = user;
		}
		@Override public StringBuilder build(boolean isLike) {
			user.setHandle(arg(isLike, user.getHandle()));
			return super.build(isLike);
		}
	}
	public static class EmailConditionBuilder extends PlaceHolderConditionBuilder {
		protected User user;
		public EmailConditionBuilder(StringBuilder buffer, User user) {
			super(buffer, "LOWER(e.address)", "LOWER(:u.email)");
			this.user = user;
		}
		@Override public StringBuilder build(boolean isLike) {
			user.setEmail(arg(isLike, user.getEmail()));
			return super.build(isLike);
		}
	}
	public static class StatusConditionBuilder extends ConditionBuilder {
		public StatusConditionBuilder(StringBuilder buffer, User user) {
			super(buffer, "u.status", user.isActive() ? "'A'" : "'U'");
		}
	}
}

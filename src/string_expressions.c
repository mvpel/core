/*
   Copyright (C) Cfengine AS

   This file is part of Cfengine 3 - written and maintained by Cfengine AS.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

  To the extent this program is licensed as part of the Enterprise
  versions of Cfengine, the applicable Commerical Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.
*/

#ifdef HAVE_CONFIG_H
# include <conf.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "bool.h"
#include "string_expressions.h"

/* <var-ref> */

static StringParseResult ParseVarRef(const char *expr, int start, int end)
{
if (start + 1 < end && expr[start] == '$')
   {
   if (expr[start+1] == '(' || expr[start+1] == '{')
      {
      char closing_bracket = expr[start+1] == '(' ? ')' : '}';
      StringParseResult res = ParseStringExpression(expr, start + 2, end);
      if (res.result)
         {
         if (res.position < end && expr[res.position] == closing_bracket)
            {
            StringExpression *ret = calloc(1, sizeof(StringExpression));
            ret->op = VARREF;
            ret->val.varref.name = res.result;

            return (StringParseResult) { ret, res.position + 1 };
            }
         else
            {
            FreeStringExpression(res.result);
            return (StringParseResult) { NULL, res.position };
            }
         }
      else
         {
         return res;
         }
      }
   else
      {
      return (StringParseResult) { NULL, start + 1 };
      }
   }
else
   {
   return (StringParseResult) { NULL, start };
   }
}

/* <token> */

static bool ValidTokenCharacter(char c)
{
if (c >= 'a' && c <= 'z')
   {
   return true;
   }

if (c >= 'A' && c <= 'Z')
   {
   return true;
   }

if (c >= '0' && c <= '9')
   {
   return true;
   }

if (c == '_' || c == '[' || c == ']')
   {
   return true;
   }

return false;
}

static StringParseResult ParseToken(const char *expr, int start, int end)
{
int endlit = start;
while (endlit < end && ValidTokenCharacter(expr[endlit]))
   {
   endlit++;
   }

if (endlit > start)
   {
   StringExpression *ret = calloc(1, sizeof(StringExpression));
   ret->op = LITERAL;
   ret->val.literal.literal = strndup(expr + start, endlit - start);

   return (StringParseResult) { ret, endlit };
   }
else
   {
   return (StringParseResult) { NULL, endlit };
   }
}

/* <term> */

static StringParseResult ParseTerm(const char *expr, int start, int end)
{
StringParseResult res = ParseToken(expr, start, end);
if (res.result)
   {
   return res;
   }
else
   {
   return ParseVarRef(expr, start, end);
   }
}

/* <name> */

StringParseResult ParseStringExpression(const char *expr, int start, int end)
{
StringParseResult lhs = ParseTerm(expr, start, end);
if (lhs.result)
   {
   StringParseResult rhs = ParseStringExpression(expr, lhs.position, end);
   if (rhs.result)
      {
      StringExpression *ret = calloc(1, sizeof(StringExpression));
      ret->op = CONCAT;
      ret->val.concat.lhs = lhs.result;
      ret->val.concat.rhs = rhs.result;

      return (StringParseResult) { ret, rhs.position };
      }
   else
      {
      return lhs;
      }
   }
else
   {
   return lhs;
   }
}

/* Evaluation */

static char *EvalConcat(const StringExpression *expr, VarRefEvaluator evalfn,
                        void *param)
{
char *lhs, *rhs;

lhs = EvalStringExpression(expr->val.concat.lhs, evalfn, param);
if (!lhs)
   {
   return NULL;
   }

rhs = EvalStringExpression(expr->val.concat.rhs, evalfn, param);
if (!rhs)
   {
   free(lhs);
   return NULL;
   }

char *res = malloc(strlen(lhs) + strlen(rhs) + 1);
sprintf(res, "%s%s", lhs, rhs);
free(lhs);
free(rhs);
return res;
}

static char *EvalVarRef(const StringExpression *expr, VarRefEvaluator evalfn,
                        void *param)
{
char *name, *eval;

name = EvalStringExpression(expr->val.varref.name, evalfn, param);
if (!name)
   {
   return NULL;
   }

eval = (*evalfn)(name, param);
free(name);
return eval;
}

char *EvalStringExpression(const StringExpression *expr, VarRefEvaluator evalfn,
                           void *param)
{
switch (expr->op)
   {
   case CONCAT:
      return EvalConcat(expr, evalfn, param);
   case LITERAL:
      return strdup(expr->val.literal.literal);
   case VARREF:
      return EvalVarRef(expr, evalfn, param);
   default:
      FatalError("Unknown type of string expression"
                 "encountered during evaluation: %d", expr->op);
   }
}

/* Freeing results */

void FreeStringExpression(StringExpression *expr)
{
if (!expr)
   {
   return;
   }

switch (expr->op)
   {
   case CONCAT:
      FreeStringExpression(expr->val.concat.lhs);
      FreeStringExpression(expr->val.concat.rhs);
      break;
   case LITERAL:
      free(expr->val.literal.literal);
      break;
   case VARREF:
      FreeStringExpression(expr->val.varref.name);
      break;
   default:
      FatalError("Unknown type of string expression encountered: %d",
                 expr->op);
   }

free(expr);
}

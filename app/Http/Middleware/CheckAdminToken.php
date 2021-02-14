<?php

namespace App\Http\Middleware;

use App\Traits\GeneralTrait;
use Closure;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class CheckAdminToken
{
    use GeneralTrait;
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {

        $user = null;
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch(\Exception $e) {
            if ($e instanceof TokenInvalidException) {
                return $this->returnError('E3001','INVALID_TOKEN');
            } else if ($e instanceof TokenExpiredException) {
                return $this->returnError('E3001','EXPIRED_TOKEN');
            } else {
                return $this->returnError('E3001','TOKEN_NOTFOUND');
            }
        }

        if (!$user)
            return $this->returnError('E3001','Unauthenticated');
        return $next($request);
    }
}

<?php

namespace App\Http\Controllers\Api\User;

use App\Http\Controllers\Controller;
use App\Traits\GeneralTrait;
use Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    use GeneralTrait;
    public function login(Request $request)
    {
        try {

            // validation

            $rules = [
                "email"    => "required",
                "password" => "required"
            ];

            $validator     = Validator::make($request->all(), $rules);

            if ($validator->fails()) {
                $code = $this->returnCodeAccordingToInput($validator);
                return $this->returnValidationError($code, $validator);
            }

            // login

            $credentials = $request->only(['email', 'password']);

            $token = Auth::guard('user-api')->attempt($credentials);

            if (!$token)
                return $this->returnError('E001', 'بيانات الدخول غير صحيحة');

            // return token

            $user = Auth::guard('user-api')->user();
            $user->api_token = $token;

            return $this->returnData('user', $user, 'تم تسجيل المستخدم بنجاح');


            // return token
        } catch (\Exception $ex) {
            return $this->returnError($ex->getCode(), $ex->getMessage());
        }
    }

    public function logout(Request $request)
    {
        $token = $request->header('auth-token');

        if ($token) {
            try {
                JWTAuth::setToken($token)->invalidate();  // logout
            } catch (TokenInvalidException $e) {
                return $this->returnError('S005', 'Some thing went wrongs');
            }
            return $this->returnSuccessMessage('Logged out successfully');
        } else {
            return $this->returnError('S005', 'Some thing went wrongs');
        }
    }
}

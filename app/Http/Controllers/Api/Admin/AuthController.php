<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use App\Models\Admin;
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
                // |exists:admins,email
            ];

            $validator     = Validator::make($request->all(), $rules);

            if ($validator->fails()) {
                $code = $this->returnCodeAccordingToInput($validator);
                return $this->returnValidationError($code, $validator);
            }

            // login

            $credentials = $request->only(['email', 'password']);

            $token = Auth::guard('admin-api')->attempt($credentials);

            if (!$token)
                return $this->returnError('E001', 'بيانات الدخول غير صحيحة');

            // return token

            $admin = Auth::guard('admin-api')->user();
            $admin->api_token = $token;

            return $this->returnData('admin', $admin, 'تم تسجيل الادمن بنجاح');


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

<?php

namespace App\Http\Controllers;

use App\Models\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\Models\Auth\ModelHasRoles;

class ApiController extends Controller
{
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        $message = 'Login successfully';

        return response()->json(compact('message', 'token'), 200);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string|max:191',
            'last_name' => 'required|string|max:191',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create([
            'first_name' => $request->get('first_name'),
            'last_name' => $request->get('last_name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
            'confirmed' => 1,
        ]);

        if(!empty($user)) {
            $model_role = new ModelHasRoles;
            $model_role->role_id = 3;
            $model_role->model_type = 'App\Models\Auth\User';
            $model_role->model_id = $user->id;
            $model_role->save();
        }

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('user','token'),201);
    }

    public function getAuthenticatedUser()
    {
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
                return response()->json(['token_absent'], $e->getStatusCode());
        }
        return response()->json(compact('user'));
    }

    public function getUserProfile($id = 0)
    { 
        $get_profile = User::find($id);
        if(empty($get_profile))
            return response()->json(['not_found'], 404);

        return response()->json(compact('get_profile'));
    }

    public function updateAuthenticatedUser(Request $request)
    { 
        $arrInput = $request->all();

        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }

            $rules = [
                'first_name' => 'required|string|max:191',
                'last_name' => 'required|string|max:191',
            ];

            if (!empty($request->input('email')))
                $rules['email'] = 'required|string|email|max:255|unique:users';
            
            if (!empty($request->input('password')))
                $rules['password'] = 'required|string|min:6|confirmed';
            
            $validator = Validator::make($request->all(), $rules);

            if($validator->fails()){
                return response()->json($validator->errors()->toJson(), 400);
            }

            $user->first_name = $request->get('first_name');
            $user->last_name = $request->get('last_name');
            if (!empty($request->get('email')))
                $user->email = $request->get('email');
            if (!empty($request->get('password')))
                $user->password = Hash::make($request->get('password'));

            if(!empty($arrInput['avatar'])) {
                $files = $this->UploadFile($arrInput['avatar'], 'upload/user');
                if(!empty($files)) {
                    $user->avatar_type = $files['type'];
                    $user->avatar_location = $files['path'];
                }
            }
            $user->save();

        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
                return response()->json(['token_absent'], $e->getStatusCode());
        }
        return response()->json(compact('user'));
    }

    function UploadFile($file, $path) {
        //$arrInput = $request->all();
        //dd($file);
        //$file = $request->file('image');
        //Display File Name
        $filename = time().'_'.rand(1, 100).'_'.$file->getClientOriginalName();
        $file->getClientOriginalExtension();
        $file->getRealPath();
        $file->getSize();
        $file->getMimeType();
        //Move Uploaded File
        $destinationPath = public_path().'/'.$path;
        $file->move($destinationPath,$filename);

        return ['type' => $file->getClientOriginalExtension(), 'path' => $destinationPath.'/'.$filename];
    }
}
<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthController extends Controller
{
    private $key = 'PASSWORD_DE_MI_APLICACION'; // Asegúrate de usar una clave segura

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json(['message' => 'Usuario registrado con éxito'], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Credenciales inválidas'], 401);
        }

        $payload = [
            'sub' => $user->id,
            'iat' => time(),
            'exp' => time() + 3600
        ];

        //$token = JWT::encode($payload, $this->key, 'HS256');
        $key = env('JWT_SECRET');
        $token = JWT::encode($payload, $key, 'HS256');

        return response()->json(['token' => $token]);
    }

    // Método para renovar el token JWT
    public function refresh(Request $request)
    {
        // Obtiene el token del encabezado Authorization
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Token no proporcionado'], 401);
        }

        try {
            // Obtén la clave secreta desde el archivo .env
            $key = env('JWT_SECRET');

            // Decodifica el token usando la clave secreta y el algoritmo HS256
            $decoded = JWT::decode($token, new \Firebase\JWT\Key($key, 'HS256'));

            // Genera un nuevo payload para el token
            $payload = [
                'sub' => $decoded->sub, // ID del usuario
                'iat' => time(),        // Tiempo de emisión
                'exp' => time() + env('JWT_TTL', 3600), // Expiración (por defecto 1 hora)
            ];

            // Genera un nuevo token con el payload y la clave secreta
            $newToken = JWT::encode($payload, $key, 'HS256');

            return response()->json([
                'message' => 'Nuevo token generado exitosamente.',
                'token' => $newToken
            ], 200);

        } catch (\Firebase\JWT\ExpiredException $e) {
            // El token ha expirado
            return response()->json(['error' => 'El token ha expirado'], 401);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            // La firma del token es inválida
            return response()->json(['error' => 'La firma del token es inválida'], 401);
        } catch (\Exception $e) {
            // Otro error relacionado con el token
            return response()->json(['error' => 'Token inválido o no procesable'], 401);
        }
    }
}


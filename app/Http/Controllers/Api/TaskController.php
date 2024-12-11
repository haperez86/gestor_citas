<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Task;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;

class TaskController extends Controller
{
    private $key = 'PASSWORD_DE_MI_APLICACION'; // Asegúrate de usar la misma clave para JWT

    // Decodifica y valida el token
    protected function getUserFromToken(Request $request)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return null; // O manejar algún tipo de error
        }

        try {
            $key = env('JWT_SECRET');
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            return $decoded->sub; // Devuelve el ID del usuario del token
        } catch (\Exception $e) {
            return null;
        }
    }

    // Crear tarea
    public function store(Request $request)
    {
        $userId = $request->attributes->get('user_id');

        if (!$userId) {
            return response()->json(['error' => 'Usuario no autenticado'], 401);
        }

        $request->validate([
            'title' => 'required|string|max:255',
            'description' => 'nullable|string',
            'due_date' => 'required|date',
            'status' => 'required|in:pendiente,en progreso,completada',
        ]);

        $task = Task::create([
            'title' => $request->title,
            'description' => $request->description,
            'due_date' => $request->due_date,
            'status' => $request->status,
            'user_id' => $userId,
        ]);

        return response()->json($task, 201);
    }

    // Leer todas las tareas del usuario autenticado
    public function index(Request $request)
    {
        $userId = $this->getUserFromToken($request);
        if (!$userId) {
            return response()->json(['error' => 'Token inválido'], 401);
        }

        $tasks = Task::where('user_id', $userId)->get();
        return response()->json($tasks);
    }

    // Actualizar una tarea específica
    public function update(Request $request, $id)
    {
        $userId = $this->getUserFromToken($request);
        if (!$userId) {
            return response()->json(['error' => 'Token inválido'], 401);
        }

        $task = Task::where('id', $id)->where('user_id', $userId)->first();
        if (!$task) {
            return response()->json(['error' => 'Tarea no encontrada'], 404);
        }

        $request->validate([
            'title' => 'nullable|string|max:255',
            'description' => 'nullable|string',
            'due_date' => 'nullable|date',
            'status' => 'nullable|in:pendiente,en progreso,completada',
        ]);

        $task->update($request->only(['title', 'description', 'due_date', 'status']));
        return response()->json($task);
    }

    // Eliminar una tarea específica
    public function destroy(Request $request, $id)
    {
        $userId = $this->getUserFromToken($request);
        if (!$userId) {
            return response()->json(['error' => 'Token inválido'], 401);
        }

        $task = Task::where('id', $id)->where('user_id', $userId)->first();
        if (!$task) {
            return response()->json(['error' => 'Tarea no encontrada'], 404);
        }

        $task->delete();
        return response()->json(['message' => 'Tarea eliminada con éxito']);
    }
}

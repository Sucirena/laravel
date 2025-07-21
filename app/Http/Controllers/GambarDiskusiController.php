<?php

namespace App\Http\Controllers;

use App\Models\GambarDiskusi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class GambarDiskusiController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        $gambar = GambarDiskusi::findOrFail($id);

        if (Storage::disk('public')->exists($gambar->gambar)) {
            Storage::disk('public')->delete($gambar->gambar);
        }

        $gambarDeleted = $gambar->delete();

        if ($gambarDeleted) {
            return redirect()->back()->with('success', 'Data gambar diskusi berhasil dihapus!');
        } else {
            return redirect()->back()->with('error', 'Data gambar diskusi gagal dihapus!');
        }
    }
}

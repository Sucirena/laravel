<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('konten_edukatif', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap konten edukatif
            $table->unsignedBigInteger('id_user')->nullable(); // Foreign key untuk merujuk ke pengguna yang membuat atau mengunggah konten
            $table->string('judul', 255); // Judul artikel atau konten edukatif
            $table->enum('tipe', ['artikel', 'video']); // Jenis konten
            $table->string('thumbnail', 255); // Gambar kecil (thumbnail) untuk konten
            $table->string('sumber', 255); // Sumber informasi yang digunakan untuk konten
            $table->longText('isi_artikel')->nullable(); // Isi dari artikel atau konten
            $table->string('link_youtube', 255)->nullable(); // Link ke video YouTube jika tipe konten adalah video
            $table->timestamps(); // Menambahkan kolom created_at dan updated_at

            // Menambahkan foreign key constraint untuk id_user
            $table->foreign('id_user')->references('id')->on('user')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('konten_edukatif');
    }
};

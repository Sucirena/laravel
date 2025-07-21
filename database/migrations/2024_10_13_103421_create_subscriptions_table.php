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
        Schema::create('subscriptions', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap subscription
            $table->unsignedBigInteger('id_user'); // Relasi dengan tabel users, hapus subscription jika user dihapus
            $table->timestamp('started_at'); // Tanggal mulai subscription
            $table->timestamp('ends_at')->nullable(); // Tanggal berakhir subscription (hasil dari perhitungan)
            $table->timestamps(); // Timestamps created_at dan updated_at

            // Definisi foreign key
            $table->foreign('id_user')->references('id')->on('user')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('subscriptions');
    }
};

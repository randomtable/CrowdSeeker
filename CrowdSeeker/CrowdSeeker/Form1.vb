Imports System.IO
Imports System.Net
Imports System.Text

Public Class Form1

    Dim nomefile As String = "Result.txt"

    Private Sub Form1_Load(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Load
        'processa("google.com", 10)
    End Sub

    Public Sub processa(ByVal dominio As String, ByVal deepness As Integer)
        Dim risultato As String = analizza(dominio)
        Dim dati() As String = risultato.Split(",")
        For i = 0 To dati.Length - 1
            If dati(i).Contains("DOMAIN") Then
                File.AppendAllText("Result.txt", dominio & ";" & "DOMAIN" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("IP") Then
                File.AppendAllText("Result.txt", dominio & ";" & "IP" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("EMAIL") Then
                File.AppendAllText("Result.txt", dominio & ";" & "EMAIL" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("MD5") Then
                File.AppendAllText("Result.txt", dominio & ";" & "MD5" & ";" & dati(i + 1) & ";" & "https://www.virustotal.com/gui/search/" & dati(i + 1) & vbCrLf)
            End If
        Next
        cicla(deepness)
    End Sub

    Public Sub cicla(ByVal deepness As Integer)
        If deepness = 0 Then
            Exit Sub
        End If
        For i = 0 To deepness
            Dim myFileStream As FileStream
            Dim myStreamReader As StreamReader

            Dim StreamEncoding As Encoding
            StreamEncoding = Encoding.Default

            Try
                myFileStream = New FileStream(nomefile, FileMode.Open, FileAccess.Read)
                myStreamReader = New StreamReader(myFileStream, StreamEncoding)
                nomefile = "Result" & i & ".txt"
                While myStreamReader.Peek <> -1
                    Dim stringa As String = myStreamReader.ReadLine
                    Dim datistringa() As String = stringa.Split(";")
                    Dim richiesta As String = datistringa(2)
                    Dim tipo As String = datistringa(1)
                    If tipo = "DOMAIN" Then
                        processadominio(richiesta)
                    End If
                    If tipo = "IP" Then
                        processaip(richiesta)
                    End If
                    If tipo = "EMAIL" Then
                        processaemail(richiesta)
                    End If
                    If tipo = "MD5" Then
                        processamd5(richiesta)
                    End If
                End While

            Catch ex As Exception
                MsgBox(ex.Message)
            Finally
                myStreamReader.Close()
                myFileStream.Close()
            End Try
        Next
    End Sub

    Public Function analizza(ByVal dominio As String) As String
        Dim inStream As StreamReader
        Dim wr As WebRequest
        Dim webresponse As WebResponse
        wr = WebRequest.Create("https://www.threatcrowd.org/searchApi/v1/api.php?type=domain&query=" & dominio)
        webresponse = wr.GetResponse()
        inStream = New StreamReader(webresponse.GetResponseStream())
        Return inStream.ReadToEnd()
    End Function

    Public Sub processadominio(ByVal dominio As String)
        Dim risultato As String = analizza(dominio)
        Dim dati() As String = risultato.Split(",")
        For i = 0 To dati.Length - 1
            If dati(i).Contains("DOMAIN") Then
                File.AppendAllText(nomefile, dominio & ";" & "DOMAIN" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("IP") Then
                File.AppendAllText(nomefile, dominio & ";" & "IP" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("EMAIL") Then
                File.AppendAllText(nomefile, dominio & ";" & "EMAIL" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("MD5") Then
                File.AppendAllText(nomefile, dominio & ";" & "MD5" & ";" & dati(i + 1) & ";" & "https://www.virustotal.com/gui/search/" & dati(i + 1) & vbCrLf)
            End If
        Next
    End Sub

    Public Sub processaip(ByVal dominio As String)
        Dim risultato As String = analizzaip(dominio)
        Dim dati() As String = risultato.Split(",")
        For i = 0 To dati.Length - 1
            If dati(i).Contains("DOMAIN") Then
                File.AppendAllText(nomefile, dominio & ";" & "DOMAIN" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("IP") Then
                File.AppendAllText(nomefile, dominio & ";" & "IP" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("EMAIL") Then
                File.AppendAllText(nomefile, dominio & ";" & "EMAIL" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("MD5") Then
                File.AppendAllText(nomefile, dominio & ";" & "MD5" & ";" & dati(i + 1) & ";" & "https://www.virustotal.com/gui/search/" & dati(i + 1) & vbCrLf)
            End If
        Next
    End Sub

    Public Function analizzaip(ByVal dominio As String) As String
        Dim inStream As StreamReader
        Dim wr As WebRequest
        Dim webresponse As WebResponse
        wr = WebRequest.Create("https://www.threatcrowd.org/searchApi/v1/api.php?type=ip&query=" & dominio)
        webresponse = wr.GetResponse()
        inStream = New StreamReader(webresponse.GetResponseStream())
        Return inStream.ReadToEnd()
    End Function

    Public Sub processaemail(ByVal dominio As String)
        Dim risultato As String = analizzaemail(dominio)
        Dim dati() As String = risultato.Split(",")
        For i = 0 To dati.Length - 1
            If dati(i).Contains("DOMAIN") Then
                File.AppendAllText(nomefile, dominio & ";" & "DOMAIN" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("IP") Then
                File.AppendAllText(nomefile, dominio & ";" & "IP" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("EMAIL") Then
                File.AppendAllText(nomefile, dominio & ";" & "EMAIL" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("MD5") Then
                File.AppendAllText(nomefile, dominio & ";" & "MD5" & ";" & dati(i + 1) & ";" & "https://www.virustotal.com/gui/search/" & dati(i + 1) & vbCrLf)
            End If
        Next
    End Sub

    Public Function analizzaemail(ByVal dominio As String) As String
        Dim inStream As StreamReader
        Dim wr As WebRequest
        Dim webresponse As WebResponse
        wr = WebRequest.Create("https://www.threatcrowd.org/searchApi/v1/api.php?type=email&query=" & dominio)
        webresponse = wr.GetResponse()
        inStream = New StreamReader(webresponse.GetResponseStream())
        Return inStream.ReadToEnd()
    End Function

    Public Sub processamd5(ByVal dominio As String)
        Dim risultato As String = analizzamd5(dominio)
        Dim dati() As String = risultato.Split(",")
        For i = 0 To dati.Length - 1
            If dati(i).Contains("DOMAIN") Then
                File.AppendAllText(nomefile, dominio & ";" & "DOMAIN" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("IP") Then
                File.AppendAllText(nomefile, dominio & ";" & "IP" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("EMAIL") Then
                File.AppendAllText(nomefile, dominio & ";" & "EMAIL" & ";" & dati(i + 1) & ";" & vbCrLf)
            End If
            If dati(i).Contains("MD5") Then
                File.AppendAllText(nomefile, dominio & ";" & "MD5" & ";" & dati(i + 1) & ";" & "https://www.virustotal.com/gui/search/" & dati(i + 1) & vbCrLf)
            End If
        Next
    End Sub

    Public Function analizzamd5(ByVal dominio As String) As String
        Dim inStream As StreamReader
        Dim wr As WebRequest
        Dim webresponse As WebResponse
        wr = WebRequest.Create("https://www.threatcrowd.org/searchApi/v1/api.php?type=md5&query=" & dominio)
        webresponse = wr.GetResponse()
        inStream = New StreamReader(webresponse.GetResponseStream())
        Return inStream.ReadToEnd()
    End Function

    Private Sub Button1_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button1.Click
        processa(TextBox1.Text, TextBox2.Text)
    End Sub

    Private Sub Button2_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button2.Click
        OpenFileDialog1.ShowDialog()
        Dim myFileStream As FileStream
        Dim myStreamReader As StreamReader

        Dim StreamEncoding As Encoding
        StreamEncoding = Encoding.Default

        Try
            myFileStream = New FileStream(OpenFileDialog1.FileName, FileMode.Open, FileAccess.Read)
            myStreamReader = New StreamReader(myFileStream, StreamEncoding)
            While myStreamReader.Peek <> -1
                processa(myStreamReader.ReadLine, TextBox2.Text)
            End While

        Catch ex As Exception

        Finally
            myStreamReader.Close()
            myFileStream.Close()
        End Try

    End Sub
End Class
